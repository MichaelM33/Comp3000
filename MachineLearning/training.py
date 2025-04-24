import pandas as pd
import string
import nltk
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.linear_model import LogisticRegression
from sklearn.multioutput import MultiOutputClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Download necessary NLTK data
nltk.download('punkt')

# Load your cleaned data
data = pd.read_csv(r'cleaned_data.csv')
print(data[['comment_text', 'cleaned_text']].head())

# Prepare your labels and features for multi-label classification
labels = data[['toxic', 'threat', 'insult']]  # Multi-label target columns
X = data['comment_text']

# Function to clean text (lowercase and remove punctuation)
def clean_text(text):
    text = text.lower()  # Convert to lowercase
    text = text.translate(str.maketrans('', '', string.punctuation))  # Remove punctuation
    return text

# Clean the text data
data['cleaned_text'] = data['comment_text'].apply(clean_text)

# Create a TF-IDF Vectorizer with n-grams
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),  # Unigrams and bigrams
    lowercase=True,
    stop_words='english'  # Removes standard English stop words
)
X_tfidf = vectorizer.fit_transform(data['cleaned_text'])

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_tfidf, labels, test_size=0.2, random_state=42)

# Set up Logistic Regression model and hyperparameter grid for multi-output classification
base_model = LogisticRegression(max_iter=10000, solver='liblinear')  # liblinear supports L1 and L2
multi_model = MultiOutputClassifier(base_model)

param_grid = {
    'estimator__C': [0.01, 0.1, 1, 10, 100],
    'estimator__penalty': ['l1', 'l2']
}

# Perform Grid Search for hyperparameter tuning
grid_search = GridSearchCV(multi_model, param_grid, scoring='f1_micro', cv=3)
grid_search.fit(X_train, y_train)

# Best model evaluation
best_model = grid_search.best_estimator_
y_pred = best_model.predict(X_test)

# Print evaluation metrics for each label
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=['toxic', 'threat', 'insult']))

# Plot Confusion Matrix for each label
for i, label in enumerate(['toxic', 'threat', 'insult']):
    cm = confusion_matrix(y_test.iloc[:, i], y_pred[:, i])
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Not ' + label.capitalize(), label.capitalize()],
                yticklabels=['Not ' + label.capitalize(), label.capitalize()])
    plt.title(f'Confusion Matrix for {label.capitalize()}')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.show()

# Save the trained model and vectorizer
joblib.dump(best_model, 'multi_label_bad_word_detector_model.pkl')
joblib.dump(vectorizer, 'multi_label_tfidf_vectorizer.pkl')
