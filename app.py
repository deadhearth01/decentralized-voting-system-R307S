from flask import Flask, render_template, request, redirect, url_for, session
import pymongo
import json
from web3 import Web3
from datetime import datetime
from cryptography.fernet import Fernet
import os
import serial
import time

app = Flask(__name__)
app.secret_key = "dm90aW5nc3lzdGVt"  # Change this in production!

# MongoDB connection
try:
    client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    client.server_info()  # Test the connection
    db = client["voting_db"]
    voters_collection = db["voters"]
    candidates_collection = db["candidates"]
    logins_collection = db["logins"]
    elections_collection = db["elections"]
    activities_collection = db["activities"]
    announcements_collection = db["announcements"]
    print("Connected to MongoDB!")
except pymongo.errors.ServerSelectionTimeoutError as e:
    print(f"Failed to connect to MongoDB on localhost:27017: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected MongoDB connection error: {e}")
    exit(1)

# Web3 setup (Ganache)
try:
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    if not w3.is_connected():
        raise Exception("Not connected to Ganache")
    with open("build/contracts/Voting.json") as f:
        contract_data = json.load(f)
    contract_address = w3.to_checksum_address("0xA1ce1bdaaFeeB4bf3E69afC9B3C0EC47b59857c0")  # Update with your contract address
    contract_abi = contract_data["abi"]
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    print("Connected to Ganache!")
except Exception as e:
    print(f"Failed to connect to Ganache or load contract: {e}")
    exit(1)

# Admin details (from Ganache)
ADMIN_ADDRESS = w3.to_checksum_address("0x6e827e7217237cB4869E8636f3d8dF6fC55eb680")  # Update with the deployer address from Ganache
ADMIN_PRIVATE_KEY = "0xf7964a9fd3cd2f3c92fca837f40390c973103c7ddc2ab6277f1d6c661ec83307"  # Update with the private key of the deployer address
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Encryption setup
key_file = "encryption_key.txt"
if os.path.exists(key_file):
    with open(key_file, "rb") as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(ENCRYPTION_KEY)
cipher = Fernet(ENCRYPTION_KEY)

# Fingerprint sensor setup
FINGERPRINT_PORTS = ["COM7", "COM4"]  # Possible ports for the fingerprint sensor
MAX_ATTEMPTS = 3  # Maximum attempts for fingerprint registration/verification
TIMEOUT_SECONDS = 10  # Timeout for fingerprint sensor response

def connect_to_fingerprint_sensor():
    for port in FINGERPRINT_PORTS:
        try:
            ser = serial.Serial(port, 9600, timeout=TIMEOUT_SECONDS)
            print(f"Connected to fingerprint sensor on {port}")
            return ser
        except serial.SerialException as e:
            print(f"Failed to connect to fingerprint sensor on {port}: {e}")
    return None

def read_fingerprint(ser, action="register"):
    try:
        # Simulate sending a command to the fingerprint sensor
        ser.write(f"{action}\n".encode())
        time.sleep(1)  # Wait for the sensor to process
        response = ser.readline().decode().strip()
        if not response:
            return None, "No response from sensor. Please check the sensor and try again."
        if "ERROR" in response:
            if "DIRTY" in response:
                return None, "Sensor surface is dirty. Please clean the surface and try again."
            elif "TIMEOUT" in response:
                return None, "Fingerprint scan timed out. Please try again."
            else:
                return None, "Error reading fingerprint. Please try again."
        # Simulate a successful fingerprint read (in a real scenario, this would be the fingerprint data)
        return response, None
    except serial.SerialException as e:
        return None, f"Serial communication error: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error while reading fingerprint: {str(e)}"

# Helper function to log activities
def log_activity(user_id, action, details=""):
    activities_collection.insert_one({
        "user_id": user_id,
        "action": action,
        "details": details,
        "timestamp": datetime.utcnow()
    })

# Helper function to get admin dashboard data
def get_admin_dashboard_data():
    candidates = []
    try:
        count = contract.functions.getCandidateCount().call()
        for i in range(count):
            name, votes = contract.functions.getCandidate(i).call()
            candidate = candidates_collection.find_one({"id": i}) or {}
            candidates.append({
                "id": i,
                "name": name,
                "votes": votes,
                "party": candidate.get("party", "N/A"),
                "state": candidate.get("state", "N/A"),
                "age": candidate.get("age", "N/A")
            })
    except Exception as e:
        print(f"Error fetching candidates: {e}")
    total_voters = voters_collection.count_documents({})
    total_candidates = len(candidates)
    total_votes = sum(candidate["votes"] for candidate in candidates)
    voter_turnout = (total_votes / total_voters * 100) if total_voters > 0 else 0
    chart_data = {
        "labels": [candidate["name"] for candidate in candidates],
        "votes": [candidate["votes"] for candidate in candidates]
    }
    voters = list(voters_collection.find())
    for voter in voters:
        if voter.get("has_voted", False) and "party_voted_encrypted" in voter:
            try:
                decrypted_party = cipher.decrypt(voter["party_voted_encrypted"].encode()).decode()
                voter["party_voted"] = decrypted_party
            except Exception as e:
                voter["party_voted"] = "Decryption Failed"
        else:
            voter["party_voted"] = "N/A"
    votes_by_state = {}
    for voter in voters:
        if voter.get("has_voted", False):
            state = voter.get("state", "Unknown")
            votes_by_state[state] = votes_by_state.get(state, 0) + 1
    state_chart_data = {
        "labels": list(votes_by_state.keys()),
        "votes": list(votes_by_state.values())
    }
    election = elections_collection.find_one() or {"start_date": "Not scheduled", "end_date": "Not scheduled", "status": "Not started"}
    activities = list(activities_collection.find().sort("timestamp", -1).limit(50))
    announcements = list(announcements_collection.find().sort("timestamp", -1))
    return {
        "candidates": candidates,
        "total_voters": total_voters,
        "total_candidates": total_candidates,
        "total_votes": total_votes,
        "voter_turnout": voter_turnout,
        "chart_data": chart_data,
        "state_chart_data": state_chart_data,
        "voters": voters,
        "election": election,
        "activities": activities,
        "announcements": announcements
    }

# Helper function to get candidate dashboard data
def get_candidate_dashboard_data(candidate_id):
    candidate = candidates_collection.find_one({"id": candidate_id})
    if not candidate:
        return None
    election = elections_collection.find_one() or {"start_date": "Not scheduled", "end_date": "Not scheduled", "status": "Not started"}
    announcements = list(announcements_collection.find().sort("timestamp", -1))
    activities = list(activities_collection.find({"user_id": f"candidate_{candidate_id}"}).sort("timestamp", -1).limit(50))
    
    # Get all candidates for party list
    all_candidates = []
    try:
        count = contract.functions.getCandidateCount().call()
        for i in range(count):
            name, votes = contract.functions.getCandidate(i).call()
            cand = candidates_collection.find_one({"id": i}) or {}
            all_candidates.append({
                "id": i,
                "name": name,
                "votes": votes,
                "party": cand.get("party", "N/A"),
                "state": cand.get("state", "N/A"),
                "age": cand.get("age", "N/A")
            })
    except Exception as e:
        print(f"Error fetching candidates: {e}")
    
    return {
        "candidate": candidate,
        "election": election,
        "announcements": announcements,
        "activities": activities,
        "all_candidates": all_candidates
    }

# Landing page
@app.route("/")
def landing():
    return render_template("landing.html")

# Combined login/register page for voters and candidates
@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == "POST":
        action = request.form["action"]
        voter_id = request.form["voter_id"]
        password = request.form["password"]
        login_record = {
            "voter_id": voter_id,
            "timestamp": datetime.utcnow(),
            "success": False,
            "action": action
        }

        if action == "register":
            name = request.form["name"]
            state = request.form["state"]
            if voters_collection.find_one({"voter_id": voter_id}):
                login_record["message"] = "Voter ID already registered"
                logins_collection.insert_one(login_record)
                log_activity(voter_id, "Failed Registration", "Voter ID already registered")
                return render_template("auth.html", error="Voter ID already registered!", active_tab="register")
            account = w3.eth.account.create()
            voter_address = w3.to_checksum_address(account.address)
            voter_key = account.key.hex()
            voters_collection.insert_one({
                "name": name,
                "voter_id": voter_id,
                "state": state,
                "password": password,  # In production, hash this!
                "address": voter_address,
                "private_key": voter_key,
                "has_voted": False,
                "fingerprint_registered": False,
                "created_at": datetime.utcnow()
            })
            try:
                tx = contract.functions.registerVoter(voter_address).build_transaction({
                    "from": ADMIN_ADDRESS,
                    "nonce": w3.eth.get_transaction_count(ADMIN_ADDRESS),
                    "gas": 3000000,
                    "gasPrice": w3.to_wei("20", "gwei")
                })
                signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
                tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                w3.eth.wait_for_transaction_receipt(tx_hash)
                login_record["success"] = True
                login_record["message"] = "Registration successful"
                logins_collection.insert_one(login_record)
                log_activity(voter_id, "Registration", "User registered successfully")
                session["user"] = {"voter_id": voter_id, "address": voter_address, "private_key": voter_key}
                return redirect(url_for("citizen"))
            except Exception as e:
                login_record["message"] = f"Blockchain transaction failed: {str(e)}"
                logins_collection.insert_one(login_record)
                log_activity(voter_id, "Failed Registration", f"Blockchain transaction failed: {str(e)}")
                return render_template("auth.html", error=f"Registration failed: {str(e)}", active_tab="register")

        elif action == "login":
            voter = voters_collection.find_one({"voter_id": voter_id})
            if not voter:
                login_record["message"] = "Voter ID not found"
                logins_collection.insert_one(login_record)
                log_activity(voter_id, "Failed Login", "Voter ID not found")
                return render_template("auth.html", error="Voter ID not found!", active_tab="login")
            if voter["password"] != password:
                login_record["message"] = "Incorrect password"
                logins_collection.insert_one(login_record)
                log_activity(voter_id, "Failed Login", "Incorrect password")
                return render_template("auth.html", error="Incorrect password!", active_tab="login")
            login_record["success"] = True
            login_record["message"] = "Login successful"
            logins_collection.insert_one(login_record)
            log_activity(voter_id, "Login", "User logged in successfully")
            session["user"] = {"voter_id": voter_id, "address": voter["address"], "private_key": voter["private_key"]}
            
            # Check if the user is a candidate
            candidate = candidates_collection.find_one({"voter_id": voter_id})
            if candidate:
                session["candidate"] = {"id": candidate["id"], "voter_id": voter_id}
                return redirect(url_for("candidate_dashboard", tab="details"))
            return redirect(url_for("citizen"))

    return render_template("auth.html", active_tab="login")

# Admin login
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard", tab="dashboard"))
        return render_template("admin.html", error="Wrong username or password!", is_dashboard=False)
    return render_template("admin.html", is_dashboard=False)

# Admin logout
@app.route("/admin_logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin"))

# Schedule election
@app.route("/schedule_election", methods=["POST"])
def schedule_election():
    if "admin" not in session:
        return redirect(url_for("admin"))
    start_date = request.form["start_date"]
    end_date = request.form["end_date"]
    
    # Validate dates
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
        if start >= end:
            data = get_admin_dashboard_data()
            data.update({"error": "End date must be after start date", "is_dashboard": True, "active_tab": "election"})
            return render_template("admin.html", **data)
        if start < datetime.now():
            data = get_admin_dashboard_data()
            data.update({"error": "Start date cannot be in the past", "is_dashboard": True, "active_tab": "election"})
            return render_template("admin.html", **data)
    except ValueError:
        data = get_admin_dashboard_data()
        data.update({"error": "Invalid date format", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)

    # Hash the schedule info for blockchain
    schedule_info = f"Start: {start_date}, End: {end_date}"
    schedule_hash = w3.keccak(text=schedule_info).hex()

    # Record the action on the blockchain
    try:
        tx = contract.functions.logAdminAction("ScheduleElection", schedule_hash).build_transaction({
            "from": ADMIN_ADDRESS,
            "nonce": w3.eth.get_transaction_count(ADMIN_ADDRESS),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
    except Exception as e:
        data = get_admin_dashboard_data()
        data.update({"error": f"Blockchain transaction failed: {str(e)}", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)

    elections_collection.update_one({}, {"$set": {"start_date": start_date, "end_date": end_date, "status": "Scheduled", "schedule_hash": schedule_hash}}, upsert=True)
    log_activity("admin", "Election Scheduled", f"Start: {start_date}, End: {end_date}, Hash: {schedule_hash}")
    return redirect(url_for("admin_dashboard", tab="election"))

# Edit election
@app.route("/edit_election", methods=["POST"])
def edit_election():
    if "admin" not in session:
        return redirect(url_for("admin"))
    election = elections_collection.find_one()
    if election and election["status"] in ["Ongoing", "Completed"]:
        data = get_admin_dashboard_data()
        data.update({"error": "Cannot edit an ongoing or completed election", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)

    start_date = request.form["start_date"]
    end_date = request.form["end_date"]
    
    # Validate dates
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
        if start >= end:
            data = get_admin_dashboard_data()
            data.update({"error": "End date must be after start date", "is_dashboard": True, "active_tab": "election"})
            return render_template("admin.html", **data)
        if start < datetime.now():
            data = get_admin_dashboard_data()
            data.update({"error": "Start date cannot be in the past", "is_dashboard": True, "active_tab": "election"})
            return render_template("admin.html", **data)
    except ValueError:
        data = get_admin_dashboard_data()
        data.update({"error": "Invalid date format", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)

    # Hash the updated schedule info for blockchain
    schedule_info = f"Start: {start_date}, End: {end_date}"
    schedule_hash = w3.keccak(text=schedule_info).hex()

    # Record the action on the blockchain
    try:
        tx = contract.functions.logAdminAction("EditElection", schedule_hash).build_transaction({
            "from": ADMIN_ADDRESS,
            "nonce": w3.eth.get_transaction_count(ADMIN_ADDRESS),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
    except Exception as e:
        data = get_admin_dashboard_data()
        data.update({"error": f"Blockchain transaction failed: {str(e)}", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)

    elections_collection.update_one({}, {"$set": {"start_date": start_date, "end_date": end_date, "schedule_hash": schedule_hash}}, upsert=True)
    log_activity("admin", "Election Edited", f"Start: {start_date}, End: {end_date}, Hash: {schedule_hash}")
    return redirect(url_for("admin_dashboard", tab="election"))

# Start election
@app.route("/start_election")
def start_election():
    if "admin" not in session:
        return redirect(url_for("admin"))
    election = elections_collection.find_one()
    if not election or "start_date" not in election or "end_date" not in election:
        data = get_admin_dashboard_data()
        data.update({"error": "Election must be scheduled first", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)
    
    start_date = datetime.strptime(election["start_date"], "%Y-%m-%d")
    if datetime.now() < start_date:
        data = get_admin_dashboard_data()
        data.update({"error": "Cannot start election before the scheduled start date", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)
    
    elections_collection.update_one({}, {"$set": {"status": "Ongoing"}})
    log_activity("admin", "Election Started", "Election status set to Ongoing")
    return redirect(url_for("admin_dashboard", tab="election"))

# Stop election
@app.route("/stop_election")
def stop_election():
    if "admin" not in session:
        return redirect(url_for("admin"))
    election = elections_collection.find_one()
    if not election or "end_date" not in election:
        data = get_admin_dashboard_data()
        data.update({"error": "Election must be scheduled first", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)
    
    end_date = datetime.strptime(election["end_date"], "%Y-%m-%d")
    if datetime.now() < end_date:
        data = get_admin_dashboard_data()
        data.update({"error": "Cannot stop election before the scheduled end date", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)
    
    elections_collection.update_one({}, {"$set": {"status": "Completed"}})
    log_activity("admin", "Election Stopped", "Election status set to Completed")
    return redirect(url_for("admin_dashboard", tab="election"))

# Post announcement
@app.route("/post_announcement", methods=["POST"])
def post_announcement():
    if "admin" not in session:
        return redirect(url_for("admin"))
    message = request.form["message"]
    if not message:
        data = get_admin_dashboard_data()
        data.update({"error": "Announcement message cannot be empty", "is_dashboard": True, "active_tab": "election"})
        return render_template("admin.html", **data)
    announcements_collection.insert_one({
        "message": message,
        "timestamp": datetime.utcnow()
    })
    log_activity("admin", "Announcement Posted", f"Message: {message}")
    return redirect(url_for("admin_dashboard", tab="election"))

# Add candidate
@app.route("/add_candidate", methods=["POST"])
def add_candidate():
    if "admin" not in session:
        return redirect(url_for("admin"))
    name = request.form["name"]
    party = request.form["party"]
    state = request.form["state"]
    age = request.form["age"]
    voter_id = request.form["voter_id"]
    
    # Check if voter_id exists
    voter = voters_collection.find_one({"voter_id": voter_id})
    if not voter:
        data = get_admin_dashboard_data()
        data.update({"error": "Voter ID not found", "is_dashboard": True, "active_tab": "candidates"})
        return render_template("admin.html", **data)
    
    # Hash the candidate info for blockchain
    candidate_info = f"Name: {name}, Party: {party}, State: {state}, Age: {age}"
    candidate_hash = w3.keccak(text=candidate_info).hex()

    try:
        # Add candidate to blockchain
        tx = contract.functions.addCandidate(name).build_transaction({
            "from": ADMIN_ADDRESS,
            "nonce": w3.eth.get_transaction_count(ADMIN_ADDRESS),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        # Log the admin action on the blockchain
        tx = contract.functions.logAdminAction("AddCandidate", candidate_hash).build_transaction({
            "from": ADMIN_ADDRESS,
            "nonce": w3.eth.get_transaction_count(ADMIN_ADDRESS),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        candidate_id = contract.functions.getCandidateCount().call() - 1
        candidates_collection.insert_one({
            "id": candidate_id,
            "voter_id": voter_id,
            "name": name,
            "party": party,
            "state": state,
            "age": age,
            "active": True,
            "fingerprint": None,
            "fingerprint_registered": False,
            "candidate_hash": candidate_hash
        })
    except Exception as e:
        print(f"Error adding candidate: {e}")
        data = get_admin_dashboard_data()
        data.update({"error": f"Error adding candidate: {str(e)}", "is_dashboard": True, "active_tab": "candidates"})
        return render_template("admin.html", **data)
    return redirect(url_for("admin_dashboard", tab="candidates"))

# Edit candidate (admin)
@app.route("/edit_candidate/<int:candidate_id>", methods=["POST"])
def edit_candidate(candidate_id):
    if "admin" not in session:
        return redirect(url_for("admin"))
    name = request.form["name"]
    party = request.form["party"]
    state = request.form["state"]
    age = request.form["age"]
    
    # Hash the updated candidate info for blockchain
    candidate_info = f"Name: {name}, Party: {party}, State: {state}, Age: {age}"
    candidate_hash = w3.keccak(text=candidate_info).hex()

    try:
        # Update candidate name on the blockchain
        tx = contract.functions.updateCandidateName(candidate_id, name).build_transaction({
            "from": ADMIN_ADDRESS,
            "nonce": w3.eth.get_transaction_count(ADMIN_ADDRESS),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        # Log the admin action on the blockchain
        tx = contract.functions.logAdminAction("EditCandidate", candidate_hash).build_transaction({
            "from": ADMIN_ADDRESS,
            "nonce": w3.eth.get_transaction_count(ADMIN_ADDRESS),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        candidates_collection.update_one(
            {"id": candidate_id},
            {"$set": {"name": name, "party": party, "state": state, "age": age, "candidate_hash": candidate_hash}}
        )
    except Exception as e:
        print(f"Error editing candidate: {e}")
        data = get_admin_dashboard_data()
        data.update({"error": f"Error editing candidate: {str(e)}", "is_dashboard": True, "active_tab": "candidates"})
        return render_template("admin.html", **data)
    log_activity("admin", "Candidate Edited", f"Candidate ID: {candidate_id}, Hash: {candidate_hash}")
    return redirect(url_for("admin_dashboard", tab="candidates"))

# Delete candidate
@app.route("/delete_candidate/<int:candidate_id>")
def delete_candidate(candidate_id):
    if "admin" not in session:
        return redirect(url_for("admin"))
    candidates_collection.update_one({"id": candidate_id}, {"$set": {"active": False}}, upsert=True)
    log_activity("admin", "Candidate Deleted", f"Candidate ID: {candidate_id}")
    return redirect(url_for("admin_dashboard", tab="candidates"))

# Delete user
@app.route("/delete_user/<voter_id>")
def delete_user(voter_id):
    if "admin" not in session:
        return redirect(url_for("admin"))
    voters_collection.delete_one({"voter_id": voter_id})
    log_activity(voter_id, "Deleted by Admin", "User deleted by admin")
    return redirect(url_for("admin_dashboard", tab="voters"))

# Reset voting status
@app.route("/reset_voting/<voter_id>")
def reset_voting(voter_id):
    if "admin" not in session:
        return redirect(url_for("admin"))
    voters_collection.update_one({"voter_id": voter_id}, {"$set": {"has_voted": False}})
    log_activity(voter_id, "Voting Reset by Admin", "Voting status reset by admin")
    return redirect(url_for("admin_dashboard", tab="voters"))

# Toggle fingerprint status (admin)
@app.route("/toggle_fingerprint/<voter_id>")
def toggle_fingerprint(voter_id):
    if "admin" not in session:
        return redirect(url_for("admin"))
    voter = voters_collection.find_one({"voter_id": voter_id})
    new_status = not voter.get("fingerprint_registered", False)
    voters_collection.update_one({"voter_id": voter_id}, {"$set": {"fingerprint_registered": new_status}})
    log_activity(voter_id, "Fingerprint Toggled by Admin", f"Fingerprint status set to {new_status}")
    return redirect(url_for("admin_dashboard", tab="voters"))

# Admin dashboard
@app.route("/admin_dashboard/<tab>")
def admin_dashboard(tab):
    if "admin" not in session:
        return redirect(url_for("admin"))
    data = get_admin_dashboard_data()
    data.update({"is_dashboard": True, "active_tab": tab})
    return render_template("admin.html", **data)

# Candidate dashboard
@app.route("/candidate_dashboard/<tab>")
def candidate_dashboard(tab):
    if "candidate" not in session:
        return redirect(url_for("auth"))
    candidate_id = session["candidate"]["id"]
    data = get_candidate_dashboard_data(candidate_id)
    if not data:
        return redirect(url_for("auth"))
    data.update({"is_dashboard": True, "active_tab": tab})
    return render_template("candidate.html", **data)

# Update candidate details
@app.route("/update_candidate_details/<int:candidate_id>", methods=["POST"])
def update_candidate_details(candidate_id):
    if "candidate" not in session or session["candidate"]["id"] != candidate_id:
        return redirect(url_for("auth"))
    
    name = request.form["name"]
    party = request.form["party"]
    state = request.form["state"]
    age = request.form["age"]
    
    # Validate inputs
    if not all([name, party, state, age]):
        data = get_candidate_dashboard_data(candidate_id)
        data.update({"error": "All fields are required", "is_dashboard": True, "active_tab": "details"})
        return render_template("candidate.html", **data)
    
    try:
        age = int(age)
        if age < 18:
            data = get_candidate_dashboard_data(candidate_id)
            data.update({"error": "Age must be 18 or above", "is_dashboard": True, "active_tab": "details"})
            return render_template("candidate.html", **data)
    except ValueError:
        data = get_candidate_dashboard_data(candidate_id)
        data.update({"error": "Age must be a valid number", "is_dashboard": True, "active_tab": "details"})
        return render_template("candidate.html", **data)

    candidates_collection.update_one(
        {"id": candidate_id},
        {"$set": {"name": name, "party": party, "state": state, "age": age}}
    )
    log_activity(f"candidate_{candidate_id}", "Details Updated", f"Updated details: Name={name}, Party={party}, State={state}, Age={age}")
    return redirect(url_for("candidate_dashboard", tab="details"))

# Register fingerprint
@app.route("/register_fingerprint/<int:candidate_id>", methods=["POST"])
def register_fingerprint(candidate_id):
    if "candidate" not in session or session["candidate"]["id"] != candidate_id:
        return redirect(url_for("auth"))
    
    ser = connect_to_fingerprint_sensor()
    if not ser:
        data = get_candidate_dashboard_data(candidate_id)
        data.update({"error": "Fingerprint sensor not detected. Please check the connection and try again.", "is_dashboard": True, "active_tab": "biometric"})
        return render_template("candidate.html", **data)
    
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        fingerprint_data, error = read_fingerprint(ser, "register")
        if fingerprint_data:
            candidates_collection.update_one(
                {"id": candidate_id},
                {"$set": {"fingerprint": fingerprint_data, "fingerprint_registered": True}}
            )
            log_activity(f"candidate_{candidate_id}", "Fingerprint Registered", "Fingerprint successfully registered")
            ser.close()
            return redirect(url_for("candidate_dashboard", tab="biometric"))
        else:
            attempts += 1
            if attempts == MAX_ATTEMPTS:
                ser.close()
                data = get_candidate_dashboard_data(candidate_id)
                data.update({"error": f"Failed to register fingerprint after {MAX_ATTEMPTS} attempts: {error}", "is_dashboard": True, "active_tab": "biometric"})
                return render_template("candidate.html", **data)
            time.sleep(1)  # Wait before retrying
    
    ser.close()
    data = get_candidate_dashboard_data(candidate_id)
    data.update({"error": "Unexpected error during fingerprint registration", "is_dashboard": True, "active_tab": "biometric"})
    return render_template("candidate.html", **data)

# Update fingerprint
@app.route("/update_fingerprint/<int:candidate_id>", methods=["POST"])
def update_fingerprint(candidate_id):
    if "candidate" not in session or session["candidate"]["id"] != candidate_id:
        return redirect(url_for("auth"))
    
    ser = connect_to_fingerprint_sensor()
    if not ser:
        data = get_candidate_dashboard_data(candidate_id)
        data.update({"error": "Fingerprint sensor not detected. Please check the connection and try again.", "is_dashboard": True, "active_tab": "biometric"})
        return render_template("candidate.html", **data)
    
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        fingerprint_data, error = read_fingerprint(ser, "update")
        if fingerprint_data:
            candidates_collection.update_one(
                {"id": candidate_id},
                {"$set": {"fingerprint": fingerprint_data}}
            )
            log_activity(f"candidate_{candidate_id}", "Fingerprint Updated", "Fingerprint successfully updated")
            ser.close()
            return redirect(url_for("candidate_dashboard", tab="biometric"))
        else:
            attempts += 1
            if attempts == MAX_ATTEMPTS:
                ser.close()
                data = get_candidate_dashboard_data(candidate_id)
                data.update({"error": f"Failed to update fingerprint after {MAX_ATTEMPTS} attempts: {error}", "is_dashboard": True, "active_tab": "biometric"})
                return render_template("candidate.html", **data)
            time.sleep(1)  # Wait before retrying
    
    ser.close()
    data = get_candidate_dashboard_data(candidate_id)
    data.update({"error": "Unexpected error during fingerprint update", "is_dashboard": True, "active_tab": "biometric"})
    return render_template("candidate.html", **data)

# Verify fingerprint before voting
def verify_fingerprint(candidate_id):
    candidate = candidates_collection.find_one({"id": candidate_id})
    if not candidate or not candidate.get("fingerprint_registered", False):
        return False, "Fingerprint not registered. Please register your fingerprint first."
    
    ser = connect_to_fingerprint_sensor()
    if not ser:
        return False, "Fingerprint sensor not detected. Please check the connection and try again."
    
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        fingerprint_data, error = read_fingerprint(ser, "verify")
        if fingerprint_data:
            if fingerprint_data == candidate["fingerprint"]:
                ser.close()
                return True, None
            else:
                attempts += 1
                if attempts == MAX_ATTEMPTS:
                    ser.close()
                    return False, f"Fingerprint verification failed after {MAX_ATTEMPTS} attempts: Fingerprint does not match."
                time.sleep(1)  # Wait before retrying
        else:
            attempts += 1
            if attempts == MAX_ATTEMPTS:
                ser.close()
                return False, f"Fingerprint verification failed after {MAX_ATTEMPTS} attempts: {error}"
            time.sleep(1)  # Wait before retrying
    
    ser.close()
    return False, "Unexpected error during fingerprint verification"

# Cast vote (candidate)
@app.route("/candidate_vote/<int:candidate_id>", methods=["GET"])
def candidate_vote(candidate_id):
    if "candidate" not in session or "user" not in session:
        return redirect(url_for("auth"))
    
    voter_id = session["user"]["voter_id"]
    election = elections_collection.find_one()
    if not election or election["status"] != "Ongoing":
        data = get_candidate_dashboard_data(session["candidate"]["id"])
        data.update({"error": "Election is not currently ongoing", "is_dashboard": True, "active_tab": "cast_vote"})
        return render_template("candidate.html", **data)
    
    voter = voters_collection.find_one({"voter_id": voter_id})
    if voter["has_voted"]:
        log_activity(f"candidate_{session['candidate']['id']}", "Failed Vote", "User has already voted")
        data = get_candidate_dashboard_data(session["candidate"]["id"])
        data.update({"error": "You have already voted!", "is_dashboard": True, "active_tab": "cast_vote"})
        return render_template("candidate.html", **data)
    
    # Verify fingerprint
    success, error = verify_fingerprint(session["candidate"]["id"])
    if not success:
        log_activity(f"candidate_{session['candidate']['id']}", "Failed Vote", f"Fingerprint verification failed: {error}")
        data = get_candidate_dashboard_data(session["candidate"]["id"])
        data.update({"error": error, "is_dashboard": True, "active_tab": "cast_vote"})
        return render_template("candidate.html", **data)
    
    try:
        tx = contract.functions.vote(candidate_id).build_transaction({
            "from": voter["address"],
            "nonce": w3.eth.get_transaction_count(voter["address"]),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, voter["private_key"])
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        # Encrypt the party voted for
        candidate = candidates_collection.find_one({"id": candidate_id})
        party = candidate.get("party", "N/A")
        encrypted_party = cipher.encrypt(party.encode()).decode()

        voters_collection.update_one(
            {"voter_id": voter_id},
            {"$set": {"has_voted": True, "party_voted_encrypted": encrypted_party}}
        )
        log_activity(f"candidate_{session['candidate']['id']}", "Vote", f"Voted for candidate ID {candidate_id}")
    except Exception as e:
        print(f"Error voting: {e}")
        log_activity(f"candidate_{session['candidate']['id']}", "Failed Vote", f"Blockchain transaction failed: {str(e)}")
        data = get_candidate_dashboard_data(session["candidate"]["id"])
        data.update({"error": f"Error voting: {str(e)}", "is_dashboard": True, "active_tab": "cast_vote"})
        return render_template("candidate.html", **data)
    
    return redirect(url_for("candidate_dashboard", tab="cast_vote"))

# Citizen dashboard
@app.route("/citizen")
def citizen():
    if "user" not in session:
        return redirect(url_for("auth"))
    
    voter_id = session["user"]["voter_id"]
    voter = voters_collection.find_one({"voter_id": voter_id})
    if not voter:
        return redirect(url_for("auth"))  # Log out if voter not found

    # Get election details
    election = elections_collection.find_one() or {
        "start_date": "Not scheduled",
        "end_date": "Not scheduled",
        "status": "Not started"
    }

    # Get announcements
    announcements = list(announcements_collection.find().sort("timestamp", -1))

    # Check voter status
    has_voted = voter.get("has_voted", False)

    # Get candidates if election is ongoing
    candidates = []
    if election["status"] == "Ongoing":
        try:
            count = contract.functions.getCandidateCount().call()
            for i in range(count):
                name, votes = contract.functions.getCandidate(i).call()
                candidate = candidates_collection.find_one({"id": i}) or {}
                candidates.append({
                    "id": i,
                    "name": name,
                    "votes": votes,
                    "party": candidate.get("party", "N/A"),
                    "state": candidate.get("state", "N/A"),
                    "age": candidate.get("age", "N/A")
                })
        except Exception as e:
            print(f"Error fetching candidates: {e}")
            return render_template("citizen.html", 
                                 error="Error fetching candidates", 
                                 election=election, 
                                 announcements=announcements, 
                                 has_voted=has_voted)

    return render_template("citizen.html",
                         candidates=candidates,
                         election=election,
                         announcements=announcements,
                         has_voted=has_voted,
                         voter_id=voter_id)

# Vote action (citizen)
@app.route("/vote/<int:candidate_id>")
def vote(candidate_id):
    if "user" not in session:
        return redirect(url_for("auth"))
    election = elections_collection.find_one()
    if not election or election["status"] != "Ongoing":
        return render_template("citizen.html", error="Election is not currently ongoing")
    voter = voters_collection.find_one({"voter_id": session["user"]["voter_id"]})
    if voter["has_voted"]:
        log_activity(voter["voter_id"], "Failed Vote", "User has already voted")
        return render_template("citizen.html", error="You have already voted!")
    try:
        tx = contract.functions.vote(candidate_id).build_transaction({
            "from": voter["address"],
            "nonce": w3.eth.get_transaction_count(voter["address"]),
            "gas": 3000000,
            "gasPrice": w3.to_wei("20", "gwei")
        })
        signed_tx = w3.eth.account.sign_transaction(tx, voter["private_key"])
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        # Encrypt the party voted for
        candidate = candidates_collection.find_one({"id": candidate_id})
        party = candidate.get("party", "N/A")
        encrypted_party = cipher.encrypt(party.encode()).decode()

        voters_collection.update_one(
            {"voter_id": voter["voter_id"]},
            {"$set": {"has_voted": True, "party_voted_encrypted": encrypted_party}}
        )
        log_activity(voter["voter_id"], "Vote", f"Voted for candidate ID {candidate_id}")
    except Exception as e:
        print(f"Error voting: {e}")
        log_activity(voter["voter_id"], "Failed Vote", f"Blockchain transaction failed: {str(e)}")
        return render_template("citizen.html", error=f"Error voting: {str(e)}")
    return redirect(url_for("citizen"))

# Candidate logout
@app.route("/candidate_logout")
def candidate_logout():
    session.pop("candidate", None)
    session.pop("user", None)
    return redirect(url_for("auth"))

# Citizen logout
@app.route("/citizen_logout")
def citizen_logout():
    session.pop("user", None)
    return redirect(url_for("auth"))

if __name__ == "__main__":
    app.run(debug=True)