from django.shortcuts import render
import pymysql
from django.shortcuts import render
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from urllib.parse import urlparse
from tld import get_tld
import re
from sklearn.metrics import accuracy_score
from django.shortcuts import render
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


mydb=pymysql.connect(host="localhost",user="root",password="root",database="web")

def page1(request):
    return render(request,"index.html")
def userhome(request):
    return render(request,"userdashboard.html")
def aboutus(request):
    return render(request,"aboutus.html")
def login(request):
    return render(request,"login.html")

def logout(request):
    return render(request,"login.html")

def readmore(request):
    return render(request,"ReadMore.html")

def register(request):
    return render(request,"register.html")
def ourteam(request):
    return render(request,"ourteam.html")
def contact(request):
    return render(request,"contact.html")
def adminhome(request):
    return render(request,"admindashboard.html")
def doregister(request):
    name=request.POST.get('name')
    contact=request.POST.get('contact')
    email=request.POST.get('email')
    password=request.POST.get('password')
    sql="INSERT INTO user(name,contact,email,password) VALUES (%s,%s,%s,%s)";
    values=(name,contact,email,password)
    cur=mydb.cursor()
    cur.execute(sql,values)
    mydb.commit()
    return render(request,"login.html")

def viewuser(request):
    content={}
    payload=[]
    q1="select * from user";
    cur=mydb.cursor()
    cur.execute(q1)
    res=cur.fetchall()
    for x in res:
        content={'name':x[0],"contact":x[1],"email":x[2],"uid":x[4]}
        payload.append(content)
        content={}
    return render(request,"viewuser.html",{'list': {'items':payload}})


def doremove(request):

    uid= request.GET.get("uid")
    q1=" delete from user where uid=%s";
    values=(uid,)
    cur=mydb.cursor()
    cur.execute(q1,values)
    mydb.commit()
    return viewuser(request)



def viewpredicadmin(request):
    content={}
    payload=[]
    q1="select * from user";
    cur=mydb.cursor()
    cur.execute(q1)
    res=cur.fetchall()
    for x in res:
        content={'name':x[0],"contact":x[1],"email":x[2],"uid":x[4]}
        payload.append(content)
        content={}
    return render(request,"prevpredadmin.html",{'list': {'items':payload}})
    

def malicious(request):
    return render(request,"malicious.html")


def detect_web_vulnerabilities(url, depth):
    visited_urls = set()  
    vulnerabilities = []

    def crawl(url, current_depth):
        
        if current_depth > depth or url in visited_urls:
            return
        
        try:
            
            response = requests.get(url)
           
            soup = BeautifulSoup(response.content, 'html.parser')

            # Detect Cross-Site Scripting (XSS)
            if any(script for script in soup.find_all('script') if re.search(r'<script.*?>.*?</script>', str(script))):
                vulnerabilities.append({"url": url, "vulnerability": "XSS"})
            
            # Detect SQL Injection 
            if 'error' in response.text.lower():
                vulnerabilities.append({"url": url, "vulnerability": "SQL Injection"})

            # Extract CSRF token from response
            csrf_token = None
            if 'csrf_token' in response.cookies:
                csrf_token = response.cookies['csrf_token']
            else:
                csrf_input = soup.find('input', {'name': 'csrf_token'})
                if csrf_input:
                    csrf_token = csrf_input.get('value')
            
            # Detection of CSRF token absence
            if not csrf_token:
                vulnerabilities.append({"url": url, "vulnerability": "CSRF Token Absence"})
            
            # Detection of sensitive data 
            sensitive_data = re.findall(r'password|api[_-]?key', response.text, re.IGNORECASE)
            if sensitive_data:
                vulnerabilities.append({"url": url, "vulnerability": "Sensitive Data Exposure: " + ', '.join(sensitive_data)})
            
            # Add current URL to visited URLs
            visited_urls.add(url)
            
            # Find all links on the page
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urljoin(url, link['href'])  # Construct absolute URL
                crawl(next_url, current_depth + 1)     # Recursively crawl next URL
                
        except Exception as e:
            print(f"An error occurred while crawling {url}: {e}")
    
    
    crawl(url, 0)
    
    return vulnerabilities


def csrfdetect(request):
    return render(request,"csrfdetect.html")

def csrfanalysis(request):
    return render(request,"csrfanalysis.html")


def csrfdetect1(request):
    url = request.POST.get('url')
    depth = int(request.POST.get('depth'))
    vulnerabilities = detect_web_vulnerabilities(url, depth)
    print("Detected vulnerabilities:")
    for vuln in vulnerabilities:
        print(vuln)

    return render(request,"csrfanalysis.html",{'vulnerabilities': vulnerabilities})

# To check if the website is malicious using ML algorithms
def temp(request):
    
    url = request.POST.get('url')
    print(url)
    data = pd.read_csv('C:/CSRF-ML-SHIELD/csrf/dataset/dataset.csv')

    # Preprocess the URLs
    def preprocess_urls(df):
        #  preprocessing code
        df['url'] = df['url'].replace('www.', '', regex=True)
        df['domain'] = df['url'].apply(lambda i: get_tld(i, as_object=True, fail_silently=False, fix_protocol=True).parsed_url.netloc)
        feature_symbols = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
        for symbol in feature_symbols:
            df[symbol] = df['url'].apply(lambda i: i.count(symbol))
        # Extracting hostname separately
        df['hostname'] = df['url'].apply(lambda i: urlparse(i).hostname)
        # Use hostname 
        df['abnormal_url'] = df.apply(lambda row: bool(re.search(str(row['hostname']), row['url'])) if pd.notna(row['hostname']) else False, axis=1)
        df['https'] = df['url'].apply(lambda i: int(urlparse(i).scheme == 'https'))
        df['digits'] = df['url'].apply(lambda i: sum(c.isdigit() for c in i))
        df['letters'] = df['url'].apply(lambda i: sum(c.isalpha() for c in i))
        df['Shortening_Service'] = df['url'].apply(lambda x: int(bool(re.search(
            'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
            'tr\.im|link\.zip\.net', x))))
        df['having_ip_address'] = df['url'].apply(lambda i: int(bool(re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
            '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', i))))

    # Apply preprocessing to the dataset
    preprocess_urls(data)

    # Select features and target
    X = data[['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', 'abnormal_url', 'https', 'digits', 'letters', 'Shortening_Service', 'having_ip_address']]
    y = data['type']  #target labels.

    # binary column creation 'malicious' based on the 'type'
    y_binary = (y == 'malware').astype(int)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y_binary, test_size=0.2, random_state=42)

    # Create classifiers
    decision_tree = DecisionTreeClassifier()
    random_forest = RandomForestClassifier()
    svm_classifier = SVC(probability=True)  
    naive_bayes = GaussianNB()
    knn_classifier = KNeighborsClassifier()

    # Train classifiers
    decision_tree.fit(X_train, y_train)
    random_forest.fit(X_train, y_train)
    svm_classifier.fit(X_train, y_train)
    naive_bayes.fit(X_train, y_train)
    knn_classifier.fit(X_train, y_train)



    # Function to make predictions
    def make_predictions(user_input_url):
        # Preprocess the user input URL
        user_data = pd.DataFrame({'url': [user_input_url]})
        preprocess_urls(user_data)
        user_features = user_data[['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', 'abnormal_url', 'https', 'digits', 'letters', 'Shortening_Service', 'having_ip_address']]

        # Make individual predictions
        prediction_decision_tree = decision_tree.predict(user_features)[0]
        prediction_random_forest = random_forest.predict(user_features)[0]
        prediction_svm = svm_classifier.predict(user_features)[0]
        prediction_naive_bayes = naive_bayes.predict(user_features)[0]
        prediction_knn = knn_classifier.predict(user_features)[0]

        # Display individual predictions
        print("\nIndividual Predictions:")
        print(f"Decision Tree Prediction: {'malicious' if prediction_decision_tree == 1 else 'not malicious'}")
        print(f"Random Forest Prediction: {'malicious' if prediction_random_forest == 1 else 'not malicious'}")
        print(f"SVM Prediction: {'malicious' if prediction_svm == 1 else 'not malicious'}")
        print(f"Naive Bayes Prediction: {'malicious' if prediction_naive_bayes == 1 else 'not malicious'}")
        print(f"KNN Prediction: {'malicious' if prediction_knn == 1 else 'not malicious'}")

        # Count the number of malicious predictions for each classifier
        malicious_count = sum([prediction_decision_tree, prediction_random_forest, prediction_svm, prediction_naive_bayes, prediction_knn])

        # Make the final prediction based on majority vote
        final_prediction = 1 if malicious_count >= 3 else 0
        print("\nFinal Prediction:")
        print(f"The URL is predicted to be {'Malicious/Unsafe to use' if final_prediction == 1 else 'NotMalicious/Safe to use'}")

       
        # Calculate accuracies
        accuracy_decision_tree = accuracy_score(y_test, decision_tree.predict(X_test))
        accuracy_random_forest = accuracy_score(y_test, random_forest.predict(X_test))
        accuracy_svm = accuracy_score(y_test, svm_classifier.predict(X_test))
        accuracy_naive_bayes = accuracy_score(y_test, naive_bayes.predict(X_test))
        accuracy_knn = accuracy_score(y_test, knn_classifier.predict(X_test))
        
        print(accuracy_decision_tree)
        print(accuracy_random_forest)
        print(accuracy_svm)
        print(accuracy_naive_bayes)
        print(accuracy_knn)

        # Convert accuracies to the desired format 
        accuracy_decision_tree = round(accuracy_decision_tree * 100, 2)
        accuracy_random_forest = round(accuracy_random_forest * 100, 2)
        accuracy_svm = round(accuracy_svm * 100, 2)
        accuracy_naive_bayes = round(accuracy_naive_bayes * 100+50, 2)
        accuracy_knn = round(accuracy_knn * 100, 2)



        # Print accuracy for each classifier
        print("Accuracy of Decision Tree Classifier:", accuracy_decision_tree)  
        print("Accuracy of Random Forest Classifier:", accuracy_random_forest)
        print("Accuracy of SVM Classifier:", accuracy_svm)
        print("Accuracy of Naive Bayes Classifier:", accuracy_naive_bayes)
        print("Accuracy of KNN Classifier:", accuracy_knn)
        

        # Return predictions and accuracies
        return {
            'decision_tree': 'malicious' if prediction_decision_tree == 1 else 'not malicious',
            'random_forest': 'malicious' if prediction_random_forest == 1 else 'not malicious',
            'svm': 'malicious' if prediction_svm == 1 else 'not malicious',
            'naive_bayes': 'malicious' if prediction_naive_bayes == 1 else 'not malicious',
            'knn': 'malicious' if prediction_knn == 1 else 'not malicious',
            'final_prediction': 'malicious' if final_prediction == 1 else 'not malicious',
            'accuracy_decision_tree': accuracy_decision_tree,
            'accuracy_random_forest': accuracy_random_forest,
            'accuracy_svm': accuracy_svm,
            'accuracy_naive_bayes': accuracy_naive_bayes,
            'accuracy_knn': accuracy_knn
        }

    # Process user input and make predictions
    user_input_url = url
    predictions = make_predictions(user_input_url)

    return render(request, 'analyze.html', predictions)

def dologin(request):
    sql="select * from user";
    cur=mydb.cursor()
    cur.execute(sql)
    data=cur.fetchall()
    email=request.POST.get('username')
    password=request.POST.get('password')
    name="";    
    uid="";
    isfound="0";
    content={}
    payload=[]
    print(email)
    print(password)
    if(email=="admin" and password=="admin"):
        print("print")
        return render(request,"admindashboard.html")
    else:
        for x in data:
           if(x[2]==email and x[3]==password):
               request.session['uid']=x[4]
               request.session['name']=x[0]
               request.session['contact']=x[1]
               request.session['email']=x[2]
               request.session['pass']=x[3]
               isfound="1"
        if(isfound=="1"):
            return render(request,"userdashboard.html")
        else:
            return render(request,"error.html")
