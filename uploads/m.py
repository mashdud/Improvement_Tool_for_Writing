from dotenv import load_dotenv
import os
import openai

# Load environment variables
load_dotenv()

# Get and print your API key
api_key = os.getenv('OPENAI_API_KEY')
print(api_key)

# Test if it works
openai.api_key = api_key

# Try a simple API call
response = openai.ChatCompletion.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": "Hello!"}]
)
print(response.choices[0].message['content'])