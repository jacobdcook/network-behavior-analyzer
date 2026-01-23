import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

class AISummarizer:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        if self.api_key:
            self.client = Groq(api_key=self.api_key)
        else:
            self.client = None

    def summarize_anomalies(self, anomalies):
        """
        Summarize suspicious traffic flows for a human analyst using Groq.
        """
        if not anomalies:
            return "No suspicious activities detected."

        if not self.client:
            return "AI Summarization unavailable: Missing GROQ_API_KEY. Please check your .env file."

        prompt = f"""
        You are a SOC Analyst. Summarize the following network anomalies detected by a behavioral analysis tool.
        Provide a concise explanation of why this is suspicious and what the next steps should be.

        Anomalies:
        {anomalies}

        Summary:
        """

        try:
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "you are a helpful cybersecurity assistant."
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model="llama-3.3-70b-versatile",
            )
            return chat_completion.choices[0].message.content.strip()
        except Exception as e:
            return f"Error during AI summarization: {str(e)}"

if __name__ == "__main__":
    summarizer = AISummarizer()
    # print(summarizer.summarize_anomalies([{'type': 'Potential Beaconing', 'src': '192.168.1.5', 'dst': '93.184.216.34'}]))
