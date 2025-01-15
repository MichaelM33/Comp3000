from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
import gridfs
from bson.objectid import ObjectId
import urllib.parse
from datetime import datetime, timedelta
import joblib

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  


# MongoDB credentials and setup
username = os.getenv("MONGODB_USERNAME")
password = os.getenv("MONGODB_PASSWORD")
encoded_username = urllib.parse.quote_plus(username)
encoded_password = urllib.parse.quote_plus(password)
uri = f"mongodb+srv://{encoded_username}:{encoded_password}@cluster0.rmklcot.mongodb.net/SCA?compressors=snappy"


client = MongoClient(uri)
db = client['SCA']
users_collection = db['users_collection']
chats_collection = db['chats_collection']
fs = gridfs.GridFS(db)

# Allowed file extensions for profile pictures
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()  # Convert to lowercase
        password = request.form['password']

        if not all([username, password]):
            flash('Missing required fields!', 'danger')
            return redirect(url_for('login'))

        user = users_collection.find_one({"username": username})

        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['login_time'] = str(datetime.utcnow())

            # Set status to online
            users_collection.update_one(
                {"username": username},
                {"$set": {"status": "online"}}
            )


            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        display_name = request.form['display_name']
        username = request.form['username'].strip().lower()  # Convert to lowercase
        password = request.form['password']

        if not all([display_name, username, password]):
            flash('Missing required fields!', 'danger')
            return redirect(url_for('register'))

        existing_user = users_collection.find_one({"username": username})

        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user_document = {
            "display_name": display_name,
            "username": username,
            "password": hashed_password,
            "status": "online",
            "created_at": datetime.utcnow(),
            "contacts": [],
            "pending_requests": []
        }

        try:
            users_collection.insert_one(user_document)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"An error occurred: {e}")
            flash('Registration failed due to an unexpected error.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users_collection.find_one({"username": username})

    if user is None:
        flash('Session invalid. Please log in again.', 'danger')
        return redirect(url_for('login'))

    profile_pic_id = user.get("profile_pic_id")
    contact_usernames = user.get("contacts", [])
    contacts = []

    for contact_username in contact_usernames:
        contact = users_collection.find_one(
        {"username": contact_username},
        {"_id": 0, "username": 1, "display_name": 1, "status": 1, "profile_pic_id": 1}
    )
        if contact:
            # Retrieve the last message exchanged with this contact
            last_message = chats_collection.find_one(
                {"$or": [
                    {"sender": username, "receiver": contact_username},
                    {"sender": contact_username, "receiver": username}
                ]},
                sort=[("timestamp", -1)]  # Sort by timestamp in descending order
            )

            contact['last_message'] = last_message['message'] if last_message else "No messages yet"
            contacts.append(contact)

    return render_template('home.html', username=username, profile_pic_id=profile_pic_id, contacts=contacts)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if request.method == 'POST':
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']

            if profile_pic.filename == '' or not allowed_file(profile_pic.filename):
                flash('Invalid file type or no file selected!', 'danger')
                return redirect(url_for('profile'))

            user = users_collection.find_one({"username": username})
            old_pic_id = user.get("profile_pic_id")
            if old_pic_id:
                fs.delete(ObjectId(old_pic_id))

            profile_pic_id = fs.put(profile_pic, filename=f"{username}_profile_pic")
            users_collection.update_one(
                {"username": username},
                {"$set": {"profile_pic_id": str(profile_pic_id)}}
            )

            flash('Profile picture updated successfully!', 'success')

    user = users_collection.find_one({"username": username})
    profile_pic_id = user.get("profile_pic_id", None)

    return render_template('profile.html', username=username, profile_pic_id=profile_pic_id)

@app.route('/profile/<string:username>')
def view_profile(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    # Find the user by username and retrieve display name and profile picture
    user = users_collection.find_one(
        {"username": username},
        {"_id": 0, "username": 1, "display_name": 1, "profile_pic_id": 1, "created_at": 1}
    )

    if user is None:
        flash(f"User '{username}' not found.", 'danger')
        return redirect(url_for('home'))

    profile_pic_id = user.get("profile_pic_id")

    return render_template('profile_view.html', user=user, profile_pic_id=profile_pic_id)



@app.route('/profile_pic/<string:pic_id>')
def profile_pic(pic_id):
    try:
        image = fs.get(ObjectId(pic_id))
        return Response(image.read(), mimetype='image/jpeg')
    except gridfs.NoFile:
        return redirect(url_for('static', filename='default.jpg'))


@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        # Set status to offline
        users_collection.update_one(
            {"username": username},
            {"$set": {"status": "offline"}}
        )
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    # Detect if the request comes from a mobile route
    if request.referrer and '/mobile' in request.referrer:
        return redirect(url_for('mobile_login'))
    return redirect(url_for('login'))



@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        search_username = request.form['search_username']
        user = users_collection.find_one(
            {"username": search_username},
            {"_id": 0, "username": 1, "profile_pic_id": 1}
        )

        if user:
            return render_template('search.html', result=user)
        else:
            flash('User not found!', 'danger')

    return render_template('search.html')

@app.route('/send_request/<string:contact_username>', methods=['POST'])
def send_request(contact_username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    if contact_username == current_user:
        flash('You cannot send a contact request to yourself!', 'danger')
        if request.referrer and '/mobile' in request.referrer:
            return redirect(url_for('mobile_search'))
        return redirect(url_for('search'))

    if contact_username in users_collection.find_one({"username": current_user}).get("contacts", []):
        flash('This user is already in your contacts!', 'info')
        if request.referrer and '/mobile' in request.referrer:
            return redirect(url_for('mobile_search'))
        return redirect(url_for('search'))

    users_collection.update_one(
        {"username": contact_username},
        {"$push": {"pending_requests": current_user}}
    )

    flash('Contact request sent!', 'success')
    # Detect if the request comes from a mobile route
    if request.referrer and '/mobile' in request.referrer:
        return redirect(url_for('mobile_search'))
    return redirect(url_for('search'))

@app.route('/requests')
def requests():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users_collection.find_one({"username": username})

    if user is None:
        flash('Session invalid. Please log in again.', 'danger')
        return redirect(url_for('login'))

    pending_requests = user.get("pending_requests", [])
    requests_with_pics = []

    for requester in pending_requests:
        contact = users_collection.find_one(
            {"username": requester},
            {"_id": 0, "username": 1, "profile_pic_id": 1}
        )
        if contact:
            requests_with_pics.append(contact)

    return render_template('requests.html', requests=requests_with_pics)

@app.route('/accept_request/<string:requester_username>', methods=['POST'])
def accept_request(requester_username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    users_collection.update_one(
        {"username": current_user},
        {"$push": {"contacts": requester_username}, "$pull": {"pending_requests": requester_username}}
    )
    users_collection.update_one(
        {"username": requester_username},
        {"$push": {"contacts": current_user}}
    )

    flash(f'You are now contacts with {requester_username}!', 'success')
    # Detect if the request comes from a mobile route
    if request.referrer and '/mobile' in request.referrer:
        return redirect(url_for('mobile_requests'))
    return redirect(url_for('requests'))


@app.route('/remove_contact/<string:contact_username>', methods=['POST'])
def remove_contact(contact_username):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})

    current_user = session['username']

    # Remove the contact from the user's contact list
    users_collection.update_one(
        {"username": current_user},
        {"$pull": {"contacts": contact_username}}
    )

    # Also remove the current user from the contact's list
    users_collection.update_one(
        {"username": contact_username},
        {"$pull": {"contacts": current_user}}
    )

    return jsonify({'success': True, 'message': f'Contact {contact_username} removed successfully'})


@app.route('/chat/<string:contact_username>')
def chat(contact_username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    # Retrieve contact's display name and profile picture ID
    contact = users_collection.find_one(
        {"username": contact_username},
        {"_id": 0, "username": 1, "display_name": 1, "profile_pic_id": 1}
    )

    if contact is None:
        flash(f"User '{contact_username}' not found.", 'danger')
        return redirect(url_for('home'))

    contact_profile_pic_id = contact.get("profile_pic_id")

    # Retrieve chat history
    chat_history = list(chats_collection.find({
        "$or": [
            {"sender": current_user, "receiver": contact_username},
            {"sender": contact_username, "receiver": current_user}
        ]
    }).sort("timestamp", 1))

    # Mark all unread messages as read
    chats_collection.update_many(
        {"sender": contact_username, "receiver": current_user, "read": False},
        {"$set": {"read": True}}
    )

    return render_template('chat_content.html',
                           contact=contact,
                           contact_profile_pic_id=contact_profile_pic_id,
                           chat_history=chat_history)




@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users_collection.find_one({"username": username})

    if request.method == 'POST':
        new_display_name = request.form.get('new_display_name')
        new_password = request.form.get('new_password')

        if new_display_name:
            users_collection.update_one({"username": username}, {"$set": {"display_name": new_display_name}})
            flash('Display name updated successfully!', 'success')

        if new_password:
            hashed_password = generate_password_hash(new_password)
            users_collection.update_one({"username": username}, {"$set": {"password": hashed_password}})
            flash('Password updated successfully!', 'success')

        return redirect(url_for('settings'))

    return render_template('settings.html', display_name=user.get('display_name'))



#-=-=-=-=-=-=--------------------------------------
#-=-=-=-=-=-=--------------------------------------
#-=-=-=-=-=-=--------------------------------------
#-=-=-=-=-=-=--------------------------------------
#MOBILE SECTION


@app.route('/mobile/chat/<string:contact_username>')
def mobile_chat(contact_username):
    if 'username' not in session:
        return redirect(url_for('mobile_login'))

    current_user = session['username']

    # Retrieve chat history from MongoDB
    chat_history = list(chats_collection.find({
        "$or": [
            {"sender": current_user, "receiver": contact_username},
            {"sender": contact_username, "receiver": current_user}
        ]
    }).sort("timestamp", 1))

    # Mark all unread messages as read
    chats_collection.update_many(
        {"sender": contact_username, "receiver": current_user, "read": False},
        {"$set": {"read": True}}
    )

    return render_template('mobile_chat.html', contact_username=contact_username, chat_history=chat_history)




@app.route('/mobile/home')
def mobile_home():
    if 'username' not in session:
        return redirect(url_for('mobile_login'))

    username = session['username']
    user = users_collection.find_one({"username": username})

    if not user:
        flash('Session invalid. Please log in again.', 'danger')
        return redirect(url_for('mobile_login'))

    profile_pic_id = user.get("profile_pic_id", None)
    contacts = user.get("contacts", [])

    # Fetch contact details
    contact_details = []
    for contact in contacts:
        contact_data = users_collection.find_one(
            {"username": contact},
            {"_id": 0, "username": 1, "profile_pic_id": 1}
        )
        if contact_data:
            contact_details.append(contact_data)

    return render_template('mobile_home.html', username=username, profile_pic_id=profile_pic_id, contacts=contact_details)



@app.route('/mobile/login', methods=['GET', 'POST'])
def mobile_login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()  # Convert to lowercase
        password = request.form['password']

        if not all([username, password]):
            flash('Missing required fields!', 'danger')
            return redirect(url_for('mobile_login'))

        user = users_collection.find_one({"username": username})

        if user and check_password_hash(user['password'], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('mobile_home'))
        else:
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('mobile_login'))

    return render_template('mobile_login.html')

@app.route('/mobile/profile', methods=['GET', 'POST'])
def mobile_profile():
    if 'username' not in session:
        return redirect(url_for('mobile_login'))

    username = session['username']

    if request.method == 'POST':
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']

            if profile_pic.filename == '' or not allowed_file(profile_pic.filename):
                flash('Invalid file type or no file selected!', 'danger')
                return redirect(url_for('mobile_profile'))

            user = users_collection.find_one({"username": username})
            old_pic_id = user.get("profile_pic_id")
            if old_pic_id:
                fs.delete(ObjectId(old_pic_id))

            profile_pic_id = fs.put(profile_pic, filename=f"{username}_profile_pic")
            users_collection.update_one(
                {"username": username},
                {"$set": {"profile_pic_id": str(profile_pic_id)}}
            )

            flash('Profile picture updated successfully!', 'success')

    user = users_collection.find_one({"username": username})
    profile_pic_id = user.get("profile_pic_id", None)

    return render_template('mobile_profile.html', username=username, profile_pic_id=profile_pic_id)

@app.route('/mobile/search', methods=['GET', 'POST'])
def mobile_search():
    if 'username' not in session:
        return redirect(url_for('mobile_login'))

    if request.method == 'POST':
        search_username = request.form['search_username']
        user = users_collection.find_one(
            {"username": search_username},
            {"_id": 0, "username": 1, "profile_pic_id": 1}
        )

        if user:
            return render_template('mobile_search.html', result=user)
        else:
            flash('User not found!', 'danger')

    return render_template('mobile_search.html')

@app.route('/mobile/requests')
def mobile_requests():
    if 'username' not in session:
        return redirect(url_for('mobile_login'))

    username = session['username']
    user = users_collection.find_one({"username": username})

    if not user:
        flash('Session invalid. Please log in again.', 'danger')
        return redirect(url_for('mobile_login'))

    pending_requests = user.get("pending_requests", [])
    requests_with_pics = []

    for requester in pending_requests:
        contact = users_collection.find_one(
            {"username": requester},
            {"_id": 0, "username": 1, "profile_pic_id": 1}
        )
        if contact:
            requests_with_pics.append(contact)

    return render_template('mobile_requests.html', requests=requests_with_pics)

@app.route('/mobile/profile/<string:username>')
def mobile_profile_view(username):
    if 'username' not in session:
        return redirect(url_for('mobile_login'))

    # Fetch the user's profile from the database
    user = users_collection.find_one({"username": username}, {"_id": 0, "username": 1, "profile_pic_id": 1})

    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('mobile_home'))

    profile_pic_id = user.get("profile_pic_id", None)

    return render_template('mobile_profile_view.html', username=username, profile_pic_id=profile_pic_id)


@app.route('/mobile/logout')
def mobile_logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('mobile_login'))

#MOBILE SECTION
#-=-=-=-=-=-=--------------------------------------
#-=-=-=-=-=-=--------------------------------------
#-=-=-=-=-=-=--------------------------------------
#-=-=-=-=-=-=--------------------------------------








from flask_socketio import SocketIO, emit, join_room, leave_room


import logging
from socketio import exceptions as socketio_exceptions

# Suppress specific logging messages for disconnect errors
logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)
# Initialize SocketIO
socketio = SocketIO(app)

@socketio.on('join_room')
def handle_join_room(data):
    contact_username = data['contact_username']
    current_user = session['username']

    # Create a unique room name by combining usernames
    room = f"chat_{min(current_user, contact_username)}_{max(current_user, contact_username)}"
    join_room(room)
    print(f"{current_user} has joined room {room}")



# Load the pre-trained model and vectorizer for toxic message detection
model = joblib.load('bad_word_detector_model.pkl')
tfidf_vectorizer = joblib.load('tfidf_vectorizer.pkl')



@socketio.on('send_message')
def handle_send_message(data):
    sender = session['username']
    receiver = data['receiver']
    message = data['message']

    # Filter message using the model
    message_tfidf = tfidf_vectorizer.transform([message])
    prediction = model.predict(message_tfidf)[0]

    if prediction == 1:  # Toxic message detected
        emit('toxic_warning', {'warning': 'Your message may be considered toxic. Please rephrase.'}, room=request.sid)
        return  # Do not broadcast the message

    # Create a unique room name by combining usernames
    room = f"chat_{min(sender, receiver)}_{max(sender, receiver)}"

    # Save the message to the database
    chat_document = {
    "sender": sender,
    "receiver": receiver,
    "message": message,
    "display_name": users_collection.find_one({"username": sender})["display_name"],
    "timestamp": datetime.utcnow(),
    "delivered": True,
    "read": False
}
    chats_collection.insert_one(chat_document)

    # Broadcast the message to the room
    emit('receive_message', {
        "sender": sender,
        "message": message,
        "timestamp": chat_document['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
    }, room=room)





@socketio.on('read_receipt')
def handle_read_receipt(data):
    sender = data['sender']
    receiver = session['username']

    # Emit read receipt to the sender
    room = f"chat_{min(sender, receiver)}_{max(sender, receiver)}"
    emit('message_read', {"receiver": receiver}, room=room)


@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username:
        users_collection.update_one(
            {"username": username},
            {"$set": {"status": "offline"}}
        )
    print(f"{username} has disconnected")




if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)