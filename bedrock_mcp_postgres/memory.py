# memory.py
from collections import deque
from typing import Dict, List, Deque
from .message import Message

class ChatMemory:
    """Class to manage chat history and context"""
    
    def __init__(self, max_messages: int = 20):
        """
        Initialize chat memory
        
        Args:
            max_messages: Maximum number of messages to keep in memory
        """
        self.messages: Deque[Dict] = deque(maxlen=max_messages)
        self.max_messages = max_messages
        self.summary = ""
    
    def add_message(self, message: Dict):
        """Add a message to the chat history"""
        self.messages.append(message)
    
    def add_user_message(self, text: str):
        """Add a user message to the chat history"""
        self.add_message(Message.user(text).__dict__)
    
    def add_assistant_message(self, text: str):
        """Add an assistant message to the chat history"""
        self.add_message(Message.assistant(text).__dict__)
    
    def get_messages(self) -> List[Dict]:
        """Get all messages in the chat history"""
        return list(self.messages)
    
    def clear(self):
        """Clear the chat history"""
        self.messages.clear()
        self.summary = ""
    
    def set_summary(self, summary: str):
        """Set a summary of the conversation so far"""
        self.summary = summary
    
    def get_context_message(self) -> Dict:
        """Get a system message with context from previous conversation"""
        if not self.summary:
            return Message.user("Let's continue our conversation.").__dict__
        else:
            return Message.user(f"Let's continue our conversation. Here's a summary of what we've discussed so far: {self.summary}").__dict__