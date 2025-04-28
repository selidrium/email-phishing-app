import requests
import json
import os

def test_email_analysis():
    url = 'http://localhost:5000/analysis/analyze'
    
    # Ensure the file exists
    eml_path = 'test3.eml'
    if not os.path.exists(eml_path):
        print(f"Error: {eml_path} not found")
        return
        
    print(f"Testing with file: {eml_path}")
    files = {'file': ('test3.eml', open(eml_path, 'rb'), 'message/rfc822')}
    
    try:
        print("Sending request to:", url)
        response = requests.post(url, files=files)
        print("Response status code:", response.status_code)
        
        if response.status_code == 200:
            results = response.json()
            print("\nAnalysis Results:")
            print(json.dumps(results, indent=2))
        else:
            print(f"Error: {response.status_code}")
            print("Response text:", response.text)
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        files['file'][1].close()

if __name__ == '__main__':
    test_email_analysis() 