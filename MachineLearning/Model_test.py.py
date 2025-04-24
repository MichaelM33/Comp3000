import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# Define the tokenizer function
def simple_tokenizer(text):
    return text  # Since 'cleaned_text' is already tokenized

# Load the model and the vectorizer
model = joblib.load('bad_word_detector_model.pkl')
tfidf_vectorizer = joblib.load('tfidf_vectorizer.pkl')

# Example text to classify
sample_texts = [
    "I love dogs",
    "I want to spend time with my friends",
    "You are ugly"
   
]

# Transform the sample texts
sample_texts_tfidf = tfidf_vectorizer.transform(sample_texts)

# Make predictions
predictions = model.predict(sample_texts_tfidf)

# Display the results
for text, prediction in zip(sample_texts, predictions):
    print(f"Comment: '{text}' - Prediction: {'Toxic' if prediction == 1 else 'Not Toxic'}")
