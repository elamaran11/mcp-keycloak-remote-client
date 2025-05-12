# message.py
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class Message:
    role: str
    content: List[Dict[str, Any]]

    @classmethod
    def user(cls, text: str) -> 'Message':
        return cls(role="user", content=[{"text": text}])

    @classmethod
    def assistant(cls, text: str) -> 'Message':
        return cls(role="assistant", content=[{"text": text}])

    '''@classmethod
    def tool_result(cls, tool_use_id: str, content: str) -> 'Message':
        return cls(
            role="user",
            content=[{
                "toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"json": {"text": content}}]
                }
            }]
        )'''
    @classmethod
    @classmethod
    def tool_result(cls, tool_use_id: str, content: str) -> 'Message':
        # Ensure content is properly formatted as a list of objects
        return cls(
            role="user",
            content=[{
                "toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"text": content}]  # Always wrap in a list with text key
                }
            }]
        )




    @classmethod
    def tool_request(cls, tool_use_id: str, name: str, input_data: dict) -> 'Message':
        return cls(
            role="assistant",
            content=[{
                "toolUse": {
                    "toolUseId": tool_use_id,
                    "name": name,
                    "input": input_data
                }
            }]
        )