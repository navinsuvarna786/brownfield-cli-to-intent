import os
import yaml
try:
    import chromadb
    from chromadb.config import Settings
    from langchain_chroma import Chroma
    from langchain_openai import OpenAIEmbeddings
    try:
        from langchain_huggingface import HuggingFaceEmbeddings
    except ImportError:
        HuggingFaceEmbeddings = None

    RAG_DEPS_OK = True
except ImportError as e:
    print(f"RAG dependencies missing: {e}. RAG features disabled.")
    RAG_DEPS_OK = False
    OpenAIEmbeddings = None # type: ignore
    HuggingFaceEmbeddings = None # type: ignore
    Chroma = None # type: ignore

from langchain_core.documents import Document
from typing import List, Optional
from dotenv import load_dotenv
import logging

load_dotenv()

# --- SSL Patching Section (Run once at module level) ---
if os.getenv("DISABLE_SSL_VERIFY", "false").lower() == "true":
    print("WARNING: Disabling SSL verification (DISABLE_SSL_VERIFY=true)")
    import ssl
    import warnings
    
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    
    try:
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        
        # Suppress only the single warning from urllib3 needed.
        warnings.simplefilter('ignore', InsecureRequestWarning)
        
        # Patch Session.request to force verify=False
        _original_session_request = requests.Session.request
        
        def new_session_request(self, method, url, *args, **kwargs):
            kwargs['verify'] = False
            return _original_session_request(self, method, url, *args, **kwargs)
            
        requests.Session.request = new_session_request
        
        # Also patch requests.request api just in case
        _original_request = requests.request
        def new_request(method, url, **kwargs):
            kwargs['verify'] = False
            return _original_request(method, url, **kwargs)
        requests.request = new_request
            
    except ImportError:
        pass

class RAGSetup:
    def __init__(self, persist_directory: str = "./chroma_db"):
        self.persist_directory = persist_directory
        self.collection_name = "nac_schema_templates"

        if not RAG_DEPS_OK:
            self.embeddings = None
            return

        embedding_provider = os.getenv("EMBEDDING_PROVIDER", "openai").lower()
        
        if embedding_provider == "openai":
            if OpenAIEmbeddings is None:
                print("OpenAIEmbeddings not available. Please install langchain-openai.")
                self.embeddings = None
                return
            # Check for required environment variables
            if not os.getenv("OPENAI_API_KEY"):
                raise ValueError("OPENAI_API_KEY environment variable not set")
            
            self.embeddings = OpenAIEmbeddings(
                model=os.getenv("EMBEDDING_MODEL", "text-embedding-3-large")
            )
        
        elif embedding_provider in ["local", "huggingface"]:
            if HuggingFaceEmbeddings is None:
                print("HuggingFaceEmbeddings not available. Please install langchain-huggingface.")
                self.embeddings = None
                return

            model_name = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
            print(f"Using local embeddings model: {model_name}")
            try:
                self.embeddings = HuggingFaceEmbeddings(model_name=model_name)
            except Exception as e:
                print(f"Failed to load local embeddings model: {e}")
                self.embeddings = None
            
        else:
            print(f"Unknown embedding provider: {embedding_provider}. RAG disabled.")
            self.embeddings = None

    def load_yaml_documents(self, file_paths: List[str]) -> List[Document]:
        if not RAG_DEPS_OK:
            return []
        documents = []
        for file_path in file_paths:
            if not os.path.exists(file_path):
                print(f"Warning: File {file_path} not found.")
                continue
                
            with open(file_path, 'r') as f:
                try:
                    data = yaml.safe_load(f)
                    # Create a document for the whole file context
                    documents.append(Document(
                        page_content=yaml.dump(data),
                        metadata={"source": file_path, "type": "full_file"}
                    ))
                    
                    # Create smaller chunks for keys if possible (flatten dict)
                    if isinstance(data, dict):
                        for key, value in data.items():
                            content = yaml.dump({key: value})
                            documents.append(Document(
                                page_content=content,
                                metadata={"source": file_path, "section": key}
                            ))
                            
                            # Deep dive into catalyst_center or templates if present
                            if key == 'catalyst_center' and isinstance(value, dict):
                                for sub_key, sub_val in value.items():
                                    sub_content = yaml.dump({sub_key: sub_val})
                                    documents.append(Document(
                                        page_content=sub_content,
                                        metadata={"source": file_path, "section": f"{key}.{sub_key}"}
                                    ))

                except yaml.YAMLError as exc:
                    print(f"Error parsing YAML file {file_path}: {exc}")
        return documents

    def load_jinja_templates(self, template_dir: str) -> List[Document]:
        """Loads all .j2 Jinja2 templates from a directory."""
        if not RAG_DEPS_OK:
            return []
            
        if not os.path.exists(template_dir):
            print(f"Warning: Template directory {template_dir} not found.")
            return []
        
        import glob
        documents = []
        template_files = glob.glob(os.path.join(template_dir, "*.j2"))
        print(f"Loading {len(template_files)} templates from {template_dir}")
        
        for file_path in template_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    filename = os.path.basename(file_path)
                    
                    # Create a document describing the template and its variables
                    # We add a preamble to help the embedding model understand this is a template
                    doc_content = f"Template Name: {filename}\nType: Jinja2 Template\n\nContent:\n{content}"
                    
                    documents.append(Document(
                        page_content=doc_content,
                        metadata={"source": file_path, "type": "jinja_template", "name": filename}
                    ))
            except Exception as e:
                print(f"Error reading template {file_path}: {e}")
                
        return documents

    def create_vector_store(self, documents: List[Document]):
        if not RAG_DEPS_OK or Chroma is None:
            print("RAG disabled, skipping vector store creation.")
            return None
            
        print(f"Creating vector store with {len(documents)} documents...")
        vectorstore = Chroma.from_documents(
            documents=documents,
            embedding=self.embeddings,
            persist_directory=self.persist_directory,
            collection_name=self.collection_name
        )
        print(f"Vector store created at {self.persist_directory}")
        return vectorstore

    def get_retriever(self):
        if not RAG_DEPS_OK or Chroma is None:
            return None
            
        vectorstore = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=self.embeddings,
            collection_name=self.collection_name
        )
        return vectorstore.as_retriever(search_kwargs={"k": 3})

if __name__ == "__main__":
    # Example usage / setup script
    # Determine project root based on this script's location
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Moving up 3 levels: ai_modernization -> scripts -> nac-transform -> project_root
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
    
    rag = RAGSetup(persist_directory=os.path.join(current_dir, "chroma_db"))
    
    # Paths relative to project root
    files_to_index = [
        os.path.join(project_root, "schemas", "schema.yaml"),
        os.path.join(project_root, "nac-transform", ".schema.yaml"),
        os.path.join(project_root, "data", "templates.nac.yaml"),
    ]
    
    docs = rag.load_yaml_documents(files_to_index)
    
    # Added: Index Jinja2 templates
    template_dir = os.path.join(project_root, "nac-transform", "templates")
    template_docs = rag.load_jinja_templates(template_dir)
    docs.extend(template_docs)
    
    if docs:
        rag.create_vector_store(docs)
    else:
        print("No documents loaded. Check file paths.")
