import streamlit as st
import pickle
import numpy as np
import google.generativeai as genai

with open("Intrusion_Detector_Model.pkl", "rb") as f:
    model = pickle.load(f)

st.set_page_config(page_title="Intrusion Detector", layout="centered")

st.title("Intrusion Detection System")

st.markdown("Enter the details below to estimate the type or intrusion occurance:")

port_dic = {21:0,22:1,23:2,25:3,53:4,80:5,135:6,443:7,4444:8,6667:9,8080:10,31337:11}
request_type_dic = {'DNS':0,'FTP':1,'HTTP':2,'HTTPS':3,'SMTP':4,'SSH':5,'Telnet':6}
protocol_dic = {'ICMP':0,'TCP':1,'UDP':2}
user_agent_dic = {'Mozilla/5.0':0,'Nikto/2.1.6':1,'Wget/1.20.3':2,'curl/7.68.0:':3,'nmap/7.80':4,'python-requests/2.25.1':5}
status_dic = {"Failure":0,"Success":1}
output_dic = {0:'BotAttack',1:'Normal',2:'PortScan'}

port = st.selectbox("Port Number", [21,22,23,25,53,80,135,443,4444,6667,8080,31337])
request_type = st.selectbox("Request Type", ['DNS','FTP','HTTP','HTTPS','SMTP','SSH','Telnet'])
protocol = st.selectbox("Protocol", ['ICMP','TCP','UDP'])
user_agent = st.selectbox("User Agent", ['Mozilla/5.0','Nikto/2.1.6','Wget/1.20.3','curl/7.68.0','nmap/7.80','python-requests/2.25.1'])
status = st.selectbox("Network Status", ["Failure","Success"])
payload_size = st.number_input("Payload Size", min_value=1, step=1)

if st.button("Verify"):
    features = [[port_dic.get(port), request_type_dic.get(request_type), protocol_dic.get(protocol), user_agent_dic.get(user_agent), status_dic.get(status), payload_size]]
    prediction = model.predict(features)[0]

    detection = ""
    if prediction==1:
        detection = "No Intrution has been detected :)"
    else:
        detection = "Intrusion has been detected !!"

    model = genai.GenerativeModel('gemini-2.0-flash')
    API_KEY = st.secrets["gemini"]["api_key"]
    genai.configure(api_key=API_KEY)

    def prompt(input):
        response = model.generate_content(input)
        return response.text


    inpt = f"""
You are an AI security assistant helping users understand why a network activity was labeled as a specific type of scan.
Based on the following network request details:

    Port: {port}

    Request Type: {request_type}

    Protocol: {protocol}

    User Agent: {user_agent}

    Status: {status}

    Payload Size: {payload_size}

The system has predicted the scan type as: {output_dic.get(prediction)}.

Write a simple, 3-4 line explanation in semi-technical language for a general user explaining why this request might be considered a {output_dic.get(prediction)}.
If the predicted scan type is 'Normal', then it is safe and no intrusion has been occured.
The explanation should highlight which values are unusual or suspicious and how they relate to the detection.
    """
    
    output = prompt(inpt)

    result = f"""
    {detection}

    Intrusion Status : {output_dic.get(prediction)}

    Reason : 
    {output}
    """
    
    st.success(result)
