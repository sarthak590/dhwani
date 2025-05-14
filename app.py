from flask import Flask, render_template, request, redirect, session, jsonify
from cs50 import SQL # CS50 lib for easy database handling 
from functools import wraps
from flask_session import Session
import requests
import re # used for matching the emails
#from flask_mail import Mail, Message # For sending mails to the users
from flask_cors import CORS # To access api hosted on another domain
#from tenacity import retry, wait_random_exponential, stop_after_attempt
import google.generativeai as genai
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

gemeni_key = "Your_Gemini_api_key"


# For Spotify playback sdk
CLIENT_ID = 'Your_Client_id'
CLIENT_SECRET = 'Your_client_secret'
REDIRECT_URI = 'Your_redirect_url'
SCOPES = 'streaming user-read-email user-read-private user-modify-playback-state user-read-playback-state'


CORS(app, resources = {r"/*": {"origins": "*"}}) # Enable CORS for all resources
genai.configure(api_key=gemeni_key)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///dhawani.db")

#getting spotify access token

# Inject spotify_token into all templates
@app.context_processor
def inject_spotify_token():
    return {'spotify_token': session.get('spotify_token')}

# Client-credentials flow to fetch track details only
def get_spotify_access_token():
    """App-level token for non-playback endpoints"""
    token_url = 'https://accounts.spotify.com/api/token'
    payload = {'grant_type': 'client_credentials'}
    resp = requests.post(token_url, data=payload,
                         auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET))
    if resp.status_code == 200:
        return resp.json().get('access_token')
    else:
        return None

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

# Rendring the default page
@app.route("/")

def about():
    """Shows the about page"""
    return render_template("about.html")

@app.context_processor
def inject_username():
    user_id = session.get('user_id')
    if not user_id:
        return {}
    user = db.execute('SELECT name FROM users WHERE id = ?', user_id)
    if not user:
        return {}
    return {'username': user[0]['name']}

def extract_thumbnail(details):
    images = details.get('album', {}).get('images', []) if details else []
    return images[1]['url'] if len(images) > 1 else (images[0]['url'] if images else None)

@app.context_processor
def layout():
    """Shows the name after login"""
    user_id = session.get("user_id")
    if not user_id:
        return {}  # No user logged in, so don't inject anything.

    user = db.execute("SELECT name FROM users WHERE id = ?", user_id)
    
    if not user:  # Empty list = no user found
        return {}  # No user found, safe fallback
    username = user[0]['name']
    return{'username': username}

# Helper to pick a thumbnail URL from track details
def extract_thumbnail(details):
    images = details.get('album', {}).get('images', []) if details else []
    if images:
        return images[1]['url'] if len(images) > 1 else images[0]['url']
    return None

# Home route rendering two rows: recommended & personalized
@app.route('/home')
@login_required
def home():
    # Ensure Spotify auth
    if not session.get('spotify_token'):
        return redirect('/login_spotify')

    # Top global recommendations
    rows = db.execute(
        '''SELECT spotify_song_id AS song_id, song_name, SUM(play_count) AS total_plays
           FROM listening_stats GROUP BY spotify_song_id
           ORDER BY total_plays DESC LIMIT :limit''',
        limit=8)
    recommended_songs = []
    for r in rows:
        details = requests.get(
            f'https://api.spotify.com/v1/tracks/{r["song_id"]}',
            headers={'Authorization': f'Bearer {get_spotify_access_token()}'}
        ).json()
        recommended_songs.append({
            'uri': f"spotify:track:{r['song_id']}",
            'title': r['song_name'],
            'thumbnail_url': extract_thumbnail(details)
        })

    # Personalized top songs
    personalized_songs = []
    uid = session.get('user_id')
    user_rows = db.execute(
        '''SELECT spotify_song_id AS song_id, song_name, play_count
           FROM listening_stats WHERE user_id = :uid
           ORDER BY play_count DESC LIMIT :limit''', uid=uid, limit=8)
    for ur in user_rows:
        details = requests.get(
            f'https://api.spotify.com/v1/tracks/{ur["song_id"]}',
            headers={'Authorization': f'Bearer {get_spotify_access_token()}'}
        ).json()
        personalized_songs.append({
            'uri': f"spotify:track:{ur['song_id']}",
            'title': ur['song_name'],
            'thumbnail_url': extract_thumbnail(details)
        })

    return render_template('home.html',
                           recommended_songs=recommended_songs,
                           personalized_songs=personalized_songs)
    
    
# Users sign up / register
@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Register user"""
    if request.method == "POST":
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        # checking the fields are empty or not
        if not email or not password or not confirmation or not name:
            return "Dont Leave Any Field Empty"

        # checking the password fields match or not
        if password != confirmation:
            return "Password do not match"

        # checking if the user submitted the valid email or not
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return "Invalid email format"

        u = db.execute("SELECT email FROM users WHERE email= ?",
                        request.form.get("email"))

        # Regestring users in the database and rendring home page
        if not u:
            db.execute('INSERT INTO users (email, password, name) VALUES (?, ?, ?)', email, password, name)
            new_user_id = db.execute("SELECT id FROM users WHERE email = ?",
                                        request.form.get("email"))[0]["id"]
            session["user_id"] = new_user_id
            return redirect('/home')
        else:
            return "email already exists"
    else:
        return render_template('signup.html')
    
# Users log in
@app.route('/login', methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("email"):
            return "must provide email", 403

        # Ensure password was submitted
        elif not request.form.get("password"):
            return "must provide password", 403

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE email = ?", request.form.get("email")
        )

        # Check if the user exists and the password matches
        if len(rows) != 1 or rows[0]["password"] != request.form.get("password"):
            return "Invalid username or password"

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/home")

    else:
            return render_template('login.html')

# users can logout
@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route('/login_spotify')
def login_spotify():
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPES
    }
    auth_url = 'https://accounts.spotify.com/authorize?' + requests.compat.urlencode(params)
    return redirect(auth_url)

# To redirect 
@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return 'Authorization failed', 400
    token_data = requests.post(
        'https://accounts.spotify.com/api/token',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
    ).json()
    if 'access_token' in token_data:
        session['spotify_token'] = token_data['access_token']
        session['refresh_token'] = token_data.get('refresh_token')
        return redirect('/home')
    return f"Failed to retrieve access token: {token_data}", 400

@app.route('/articles', methods=["GET", "POST"])
@login_required
def articles():
    if request.method == "POST":
        try:
            data = request.get_json()
            title = data.get("title")
            content = data.get("content")

            print(f"DEBUG: title={title}, content={content}")  

            if not title or not content:
                return jsonify({"success": False, "error": "Please provide both a title and content."}), 400

            # Process Gemini AI check
            model = genai.GenerativeModel("gemini-1.5-flash")
            prompt = f"""
                Please determine whether the following article is about music.
                Title: {title}
                Content: {content}
                Respond with a single word: 'yes' if it is about music, or 'no' otherwise.
            """

            try:
                response = model.generate_content(prompt)
                response_text = response.candidates[0].content.parts[0].text.strip().lower()
                print(f"DEBUG: Gemini response_text={response_text}")  
            except Exception as e:
                print(f"DEBUG: Gemini API Error: {e}")
                return jsonify({"success": False, "error": "Unable to verify the article topic."}), 500

            if response_text != "yes":
                return jsonify({"success": False, "error": "Article does not appear to be about music."}), 400

            # Fetch username before inserting article
            user_data = db.execute("SELECT name FROM users WHERE id = ?", session["user_id"])
            if not user_data:
                return jsonify({"success": False, "error": "User not found."}), 400
            username = user_data[0]["name"]  # Corrected field name

            # Insert article into the database
            try:
                db.execute("INSERT INTO articles (title, content, user_id) VALUES (?, ?, ?)",
                           title, content, session["user_id"])
            except Exception as e:
                print(f"DEBUG: Database Error: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

            return jsonify({
                "success": True,
                "article": {"title": title, "content": content, "author": username}
            })

        except Exception as e:
            print(f"DEBUG: General Error: {e}")
            return jsonify({"success": False, "error": "An unexpected error occurred."}), 500

    # Fetch articles to display on the page
    articles = db.execute("SELECT title, content, users.name as author FROM articles JOIN users ON articles.user_id = users.id order by created_at desc")
    return render_template("articles.html", articles=articles)

@app.route('/search_tracks', methods=["POST"])
@login_required
def search_tracks():
    query = request.form.get("search")
    if not query:
        return jsonify({"error": "No search query provided"}), 400

    token = session.get('spotify_token')
    if not token:
        return jsonify({"error": "Spotify token missing"}), 403

    # Call Spotify's Search API
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "q": query,
        "type": "track",
        "limit": 5
    }
    response = requests.get("https://api.spotify.com/v1/search", headers=headers, params=params)
    data = response.json()

    # Extract relevant information from the top 5 tracks
    tracks = []
    for item in data.get("tracks", {}).get("items", []):
        track_info = {
            "name": item["name"],
            "artist": ", ".join([artist["name"] for artist in item["artists"]]),
            "uri": item["uri"],
            "album_image": item["album"]["images"][0]["url"] if item["album"]["images"] else ""
        }
        tracks.append(track_info)
    return jsonify(tracks)

@app.route("/like_song", methods=["POST"])
def like_song():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session["user_id"]
    song_id = request.form.get("song_id")

    if not song_id:
        return jsonify({"error": "No song id provided"}), 400

    # Get song details from Spotify API
    try:
        access_token = session.get('spotify_token')

        response = requests.get(
            f'https://api.spotify.com/v1/tracks/{song_id}',
            headers={
                'Authorization': f'Bearer {access_token}'
            }
        )
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch song details from Spotify"}), 500

        song_data = response.json()
        song_name = song_data.get('name')

        if not song_name:
            return jsonify({"error": "Song name not found in Spotify response"}), 404

        # Insert into liked_songs table
        db.execute(
            "INSERT INTO liked_songs (user_id, song_id, song_name) VALUES (?, ?, ?)",
            user_id, song_id, song_name
        )
    except Exception as e:
        return jsonify({"error": "Error processing the request: " + str(e)}), 500

    return jsonify({"success": True}), 200

# showing the liked songs
@app.route("/liked_songs")
@login_required

def liked_songs():
    user_id = session["user_id"]

    # Query the database to get the liked songs of the logged-in user
    liked_songs = db.execute("""
        SELECT song_name, song_id FROM liked_songs WHERE user_id = ? order by liked_at desc
    """, user_id)

    # If no songs are liked, display a message
    if not liked_songs:
        liked_songs = []
    # Get album art for each liked song
    songs_with_art = []
    for song in liked_songs:
        song_id = song['song_id']
        # Fetch song details from Spotify API to get album art URL
        song_details = get_song_details_from_spotify(song_id)  # Function to get song details from Spotify API
        album_art_url = song_details['album']['images'][0]['url']  # First image in the album art array
        song_with_art = {**song, 'album_art_url': album_art_url}
        songs_with_art.append(song_with_art)

    return render_template("liked_songs.html", liked_songs=songs_with_art)

def get_song_details_from_spotify(song_id):
    spotify_token = get_spotify_access_token()
    url = f"https://api.spotify.com/v1/tracks/{song_id}"
    headers = {
        "Authorization": f"Bearer {spotify_token}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()  # Return the song details, including album art URL
    else:
        return None  # Handle error or no song found

@app.route("/remove_song/<song_id>", methods=["POST"])
@login_required
def remove_song(song_id):
    user_id = session["user_id"]

    # Delete the song from the liked_songs table
    db.execute("DELETE FROM liked_songs WHERE user_id = ? AND song_id = ?", user_id, song_id)

    # Re-fetch the liked songs to make sure the page is updated with the new data
    liked_songs = db.execute("""
        SELECT song_name, song_id FROM liked_songs WHERE user_id = ? ORDER BY song_id DESC
    """, user_id)

    # If no songs are liked, display a message
    if not liked_songs:
        liked_songs = []

    # Get album art for each liked song
    songs_with_art = []
    for song in liked_songs:
        song_id = song['song_id']
        song_details = get_song_details_from_spotify(song_id)
        if song_details:
            album_art_url = song_details['album']['images'][0]['url']
            song_with_art = {**song, 'album_art_url': album_art_url}
            songs_with_art.append(song_with_art)

    # Render the updated liked_songs page with the current liked songs
    return render_template("liked_songs.html", liked_songs=songs_with_art)

# Stats page
@app.route("/stats", methods=["GET", "POST"])
@login_required
def stats():
    user_id = session.get("user_id")

    # Handle deletion of articles
    if request.method == "POST":
        article_id = request.form.get("article_id")
        if article_id:
            db.execute("DELETE FROM articles WHERE id = ? AND user_id = ?", article_id, user_id)
            return redirect("/stats")

    # Fetch user articles
    articles = db.execute("""
        SELECT id, title, content, created_at 
        FROM articles 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    """, user_id)
    
    # Fetch song listening stats for the user
    song_stats = db.execute("""
        SELECT spotify_song_id, song_name, play_count 
        FROM listening_stats 
        WHERE user_id = ? 
        ORDER BY play_count DESC 
    LIMIT 5
    """, user_id)

    # For each song, fetch album art from Spotify
    stats_with_art = []
    for song in song_stats:
        spotify_song_id = song["spotify_song_id"]
        details = get_song_details_from_spotify(spotify_song_id)
        album_art_url = ""
        if details and details.get("album", {}).get("images"):
            # Use the first image as the poster
            album_art_url = details["album"]["images"][0]["url"]
        song["album_art_url"] = album_art_url
        stats_with_art.append(song)
    
    return render_template("stats.html", articles=articles, song_stats=stats_with_art)

# deleting the articles
@app.route("/delete_article/<int:article_id>", methods=["POST"])
@login_required
def delete_article(article_id):
    user_id = session.get("user_id")
    # Delete the article if it belongs to the logged-in user
    db.execute("DELETE FROM articles WHERE id = ? AND user_id = ?", article_id, user_id)
    return redirect("/stats")

def record_song_listen(user_id, spotify_song_id):
    """
    Record a listen for the given user and Spotify song ID.
    Uses get_song_details_from_spotify to fetch the song name.
    If a record already exists, increments the play_count;
    otherwise, inserts a new record with play_count 1.
    """
    print("jlkbbbbbbbbbbbbbbbbbbbbbbbb")
    song_details = get_song_details_from_spotify(spotify_song_id)
    if not song_details:
        raise Exception("Could not fetch song details from Spotify")
    
    song_name = song_details.get("name")
    if not song_name:
        raise Exception("Song name missing from Spotify response")
    
    # Check for an existing record for this user and song
    rows = db.execute("""
        SELECT id, play_count FROM listening_stats
        WHERE user_id = ? AND spotify_song_id = ?
    """, user_id, spotify_song_id)
    
    if rows:
        # Update play count if record exists
        db.execute("""
            UPDATE listening_stats
            SET play_count = play_count + 1
            WHERE user_id = ? AND spotify_song_id = ?
        """, user_id, spotify_song_id)
    else:
        # Otherwise, insert a new record
        db.execute("""
            INSERT INTO listening_stats (user_id, spotify_song_id, song_name, play_count)
            VALUES (?, ?, ?, 1)
        """, user_id, spotify_song_id, song_name)
        
@app.route("/record_listen", methods=["POST"])
@login_required
def record_listen():
    user_id = session["user_id"]
    song_id = request.form.get("song_id")
    
    if not song_id:
        return jsonify({"error": "No song id provided"}), 400
    
    try:
        record_song_listen(user_id, song_id)
    except Exception as e:
        return jsonify({"error": "Error recording song listen: " + str(e)}), 500
    
    return jsonify({"success": True}), 200

@app.route('/is_liked')
@login_required
def is_liked():
    song_id = request.args.get('song_id')
    user_id = session['user_id']
    rows = db.execute(
        "SELECT 1 FROM liked_songs WHERE user_id = ? AND song_id = ?",
        user_id, song_id
    )
    return jsonify({ 'liked': len(rows) > 0 })
        
# Run the Flask application, Do not delete
if __name__ == '__main__':  
    app.run(debug=True)