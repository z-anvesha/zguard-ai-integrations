"""
Example: a direct-invoke summarizer with custom extractors.

When the event shape is your own, point the decorator at the exact fields your
handler reads and writes -- the scan then sees precisely what the application
sees, and a renamed field can never slip past one side but not the other.
session_id_from ties every scan of one job together in the AI Guard Console.

Invoke shape:   {"job_id": "batch-42", "document": "...text to summarize..."}
Return shape:   {"job_id": "batch-42", "summary": "..."}
"""

import os

import boto3

from aiguard_decorator import aiguard_protect

bedrock = boto3.client("bedrock-runtime")
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.amazon.nova-lite-v1:0")


@aiguard_protect(
    app_name="doc-summarizer",
    ai_model=MODEL_ID,
    prompt_from=lambda event: event.get("document"),
    response_from=lambda result: result.get("summary"),
    session_id_from=lambda event, context: event.get("job_id"),
)
def handler(event, context):
    reply = bedrock.converse(
        modelId=MODEL_ID,
        messages=[{
            "role": "user",
            "content": [{"text": "Summarize this document in three sentences:\n\n" + event["document"]}],
        }],
    )
    return {
        "job_id": event.get("job_id"),
        "summary": reply["output"]["message"]["content"][0]["text"],
    }
