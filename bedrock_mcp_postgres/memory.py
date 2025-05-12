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
    
    def validate_messages(self) -> List[Dict]:
        """
        Validate the message history to ensure toolUse and toolResult are properly paired.
        Returns a cleaned list of messages.
        """
        messages = list(self.messages)
        tool_use_ids = set()
        tool_result_ids = set()
        
        # First pass: collect all tool use and result IDs
        for msg in messages:
            if msg['role'] == 'assistant' and msg['content']:
                for item in msg['content']:
                    if 'toolUse' in item:
                        tool_use_ids.add(item['toolUse']['toolUseId'])
            
            if msg['role'] == 'user' and msg['content']:
                for item in msg['content']:
                    if 'toolResult' in item:
                        tool_result_ids.add(item['toolResult']['toolUseId'])
        
        # Second pass: filter out any tool results without matching tool uses
        valid_messages = []
        for msg in messages:
            if msg['role'] == 'user' and msg['content']:
                has_invalid_tool_result = False
                for item in msg['content']:
                    if 'toolResult' in item and item['toolResult']['toolUseId'] not in tool_use_ids:
                        has_invalid_tool_result = True
                        break
                
                if not has_invalid_tool_result:
                    valid_messages.append(msg)
            else:
                valid_messages.append(msg)
        
        return valid_messages
