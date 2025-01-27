from flask import Flask, request, render_template
import base64
import http.client
import json
from urllib.parse import urlencode
import threading
import time

app = Flask(__name__)


CLIENT_KEY = "next_3763e1a4be2dc031f68295d42615603e38"
WEBSITE_URL = "https://payment.ivacbd.com"
WEBSITE_KEY = "6LdOCpAqAAAAAOLNB3Vwt_H7Nw4GGCAbdYm5Brsb"

process = {}


def add_instance(process, instance_id, form_data, status=422, running=True):
    process[instance_id] = {
        "csrf_token": form_data.get("csrf_token"),
        "xsrf_token": form_data.get("xsrftoken"),
        "ivac_session": form_data.get("ivac_session"),
        "name1": form_data.get("name1"),
        "name2": form_data.get("name2"),
        "name3": form_data.get("name3"),
        "file1": form_data.get("fileID1"),
        "file2": form_data.get("fileID2"),
        "file3": form_data.get("fileID3"),
        "email": form_data.get("email"),
        "center_name": form_data.get("ivac_center"),
        "phone": form_data.get("phone"),
        "payment": form_data.get("payment"),
        "visa": form_data.get("visa"),
        "status": status,
        "running": running,
    }


def getCaptchaToken():
    conn1 = http.client.HTTPSConnection("api.nextcaptcha.com")
    payload1 = json.dumps(
        {
            "clientKey": "next_3763e1a4be2dc031f68295d42615603e38",
            "task": {
                "type": "Recaptchav2TaskProxyless",
                "websiteURL": "https://payment.ivacbd.com",
                "websiteKey": "6LdOCpAqAAAAAOLNB3Vwt_H7Nw4GGCAbdYm5Brsb",
            },
        }
    )
    headers1 = {"Content-Type": "application/json"}
    conn1.request("POST", "/createTask", payload1, headers1)
    res1 = conn1.getresponse()
    data1 = res1.read()
    response_json1 = json.loads(data1.decode("utf-8"))

    if response_json1.get("errorId") == 0:
        taskId = response_json1.get("taskId")
    else:
        print(f"failed to get recaptcha taskID")
    payload1 = json.dumps(
        {
            "clientKey": "next_3763e1a4be2dc031f68295d42615603e38",
            "taskId": taskId,
        }
    )
    # print(f"Captcha Obtaining for file ")
    while True:
        conn2 = http.client.HTTPSConnection("api.nextcaptcha.com")
        conn2.request("POST", "/getTaskResult", payload1, headers1)
        res2 = conn2.getresponse()
        data2 = res2.read()
        try:
            response_json2 = json.loads(data2.decode("utf-8"))
        except json.JSONDecodeError:
            print("Error: Response is not valid JSON.")
            print(f"Raw response data: {data2}")
        if response_json2.get("status") == "ready":
            return response_json2.get("solution", {}).get("gRecaptchaResponse")


@app.route("/getLinks")
def get_links():
    return json.dumps(process), 200


@app.route("/stopInstance", methods=["POST"])
def stop_instance():
    form_data = request.form.to_dict()
    instance_id = form_data.get("instance_id")
    process[instance_id]["running"] = False
    return json.dumps({"status": "Instance Stopped"}), 200


@app.route("/sendOtp", methods=["POST"])
def send_otp():
    # Proxy details
    # PROXY_HOST = "53253ad010a9a77e.tuf.as.pyproxy.io"
    # PROXY_PORT = 16666
    # PROXY_USER = "ivacapp00-zone-resi-region-bd"
    # PROXY_PASS = "ivacpassword88"

    PROXY_HOST = "http://185.230.245.187"
    PROXY_PORT = 12321
    PROXY_USER = "1eXUfMkvLXkVuu9g"
    PROXY_PASS = "metafore"
    # Parse the form data into a dictionary
    form_data = request.form.to_dict()

    def process_otp():
        # Access individual elements using their keys
        csrf_token = form_data.get("csrf_token")
        xsrf_token = form_data.get("xsrftoken")
        ivac_session = form_data.get("ivac_session")
        name1 = form_data.get("name1")
        name2 = form_data.get("name2")
        name3 = form_data.get("name3")
        file1 = form_data.get("fileID1")
        file2 = form_data.get("fileID2")
        file3 = form_data.get("fileID3")
        email = form_data.get("email")
        center_name = form_data.get("ivac_center")
        phone = form_data.get("phone")
        payment = form_data.get("payment")
        visa = form_data.get("visa")

        form_data_1 = {
            "csrf_token": csrf_token,
            "xsrftoken": xsrf_token,
            "ivac_session": ivac_session,
            "name1": name1,
            "name2": name2,
            "name3": name3,
            "fileID1": file1,
            "fileID2": file2,
            "fileID3": file3,
            "email": email,
            "ivac_center": center_name,
            "phone": phone,
            "payment": payment,
            "visa": visa,
        }

        threading.Thread(
            target=lambda: add_instance(process, file1, form_data_1)
        ).start()

        # Print the accessed elements
        print("Received Data:")
        print(f"CSRF Token: {csrf_token}")
        print(f"XSRF Token: {xsrf_token}")
        print(f"IVAC Session: {ivac_session}")
        print(f"Name: {name1}")
        print(f"File ID: {file1}")
        print(f"Name: {name2}")
        print(f"File ID: {file2}")
        print(f"Name: {name3}")
        print(f"File ID: {file3}")
        print(f"Email: {email}")
        print(f"IVAC Center: {center_name}")
        print(f"Phone: {phone}")
        print(f"Payment: {payment}")
        print(f"Visa: {visa}")

        if process[file1]["running"]:
            print("Already Running")

        if center_name == "Dhaka":
            center_id = 1
            center_prefix = "D"
            ivac_address = "Jamuna Future Park"
            ivac_app_key = "IVACJFP"
            ivac_center_info_id = 1
            ivac_id = 17
            ivac_ivac_name = "IVAC, Dhaka (JFP)"
        elif center_name == "Khulna":
            center_id = 5
            center_prefix = "K"
            ivac_address = "Dr. Motiar Rahman Tower,64, KDA Avenue,KDA Commercial Area,Banking Zone, Khulna-9100."
            ivac_app_key = "IVACKHULNA"
            ivac_center_info_id = 5
            ivac_id = 3
            ivac_ivac_name = "IVAC, KHULNA"
        elif center_name == "Rajshahi":
            center_id = 3
            center_prefix = "R"
            ivac_address = "Morium Ali Tower,Holding No-18, Plot No-557, 1ST Floor,Old Bilsimla, Greater Road,Barnali More, 1ST Floor, Ward No-10,Rajshahi."
            ivac_app_key = "IVACRAJSHAHI"
            ivac_center_info_id = 3
            ivac_id = 2
            ivac_ivac_name = "IVAC , RAJSHAHI"

        if payment == "Bkash":
            paymentlink = (
                "https://securepay.sslcommerz.com/gwprocess/v4/image/gw1/bkash.png"
            )
            paymentslug = "bkash"
        elif payment == "Nagad":
            paymentlink = (
                "https://securepay.sslcommerz.com/gwprocess/v4/image/gw1/nagad.png"
            )
            paymentslug = "nagad"
        elif payment == "NEXUS":
            paymentlink = (
                "https://securepay.sslcommerz.com/gwprocess/v4/image/gw1/dbblnexus.png"
            )
            paymentslug = "dbbl_nexus"
        elif payment == "DBBL MOBILE BANKING":
            paymentlink = "https://securepay.sslcommerz.com/gwprocess/v4/image/gw1/dbblmobilebank.png"
            paymentslug = "dbblmobilebanking"
        elif payment == "Tapnpay":
            paymentlink = (
                "https://securepay.sslcommerz.com/gwprocess/v4/image/gw1/tapnpay.png"
            )
            paymentslug = "tapnpay"

        if visa == "medical":
            visa_type_id = 13
            visa_type_name = "MEDICAL/MEDICAL ATTENDANT VISA"
            visa_order = 2
        elif visa == "student":
            visa_type_id = 2
            visa_type_name = "STUDENT VISA"
            visa_order = 6
        elif visa == "entry":
            visa_type_id = 6
            visa_type_name = "ENTRY VISA"
            visa_order = 5

        payload = {
            "_token": csrf_token,
            "action": "sendOtp",
            "apiKey": csrf_token,
            "info[0][amountChangeData][allow_old_amount_until_new_date]": 2,
            "info[0][amountChangeData][max_notification_count]": 0,
            "info[0][amountChangeData][new_fees_applied_from]": "2018-08-05 00:00:00",
            "info[0][amountChangeData][new_visa_fee]": 800.00,
            "info[0][amountChangeData][notice]": "false",
            "info[0][amountChangeData][notice_popup]": "",
            "info[0][amountChangeData][notice_short]": "",
            "info[0][amountChangeData][old_visa_fees]": 800.00,
            "info[0][amount]": 800.00,
            "info[0][captcha]": "",
            "info[0][center][c_name]": center_name,
            "info[0][center][id]": center_id,
            "info[0][center][is_delete]": 0,
            "info[0][center][prefix]": center_prefix,
            "info[0][confirm_tos]": "true",
            "info[0][email]": email,
            "info[0][is_open]": "true",
            "info[0][ivac][address]": ivac_address,
            "info[0][ivac][allow_old_amount_until_new_date]": 2,
            "info[0][ivac][app_key]": ivac_app_key,
            "info[0][ivac][ceated_on]": "2018-07-12 05:58:00",
            "info[0][ivac][center_info_id]": ivac_center_info_id,
            "info[0][ivac][charge]": 3,
            "info[0][ivac][contact_number]": "",
            "info[0][ivac][created_at]": "2018-07-12 00:00:00",
            "info[0][ivac][id]": ivac_id,
            "info[0][ivac][is_delete]": 0,
            "info[0][ivac][ivac_name]": ivac_ivac_name,
            "info[0][ivac][max_notification_count]": 2,
            "info[0][ivac][new_fees_applied_from]": "2018-08-05 00:00:00",
            "info[0][ivac][new_visa_fee]": 800.00,
            "info[0][ivac][notification_text_beside_amount]": "(From <from> this IVAC fees will be <new_amount> BDT)",
            "info[0][ivac][notification_text_popup]": "",
            "info[0][ivac][notify_fees_from]": "2018-07-29 04:54:32",
            "info[0][ivac][old_visa_fee]": 800.00,
            "info[0][ivac][prefix]": "D",
            "info[0][ivac][visa_fee]": 800.00,
            "info[0][name]": name1,
            "info[0][passport]": "",
            "info[0][phone]": phone,
            "info[0][visa_type][$hashKey]": "object:50",
            "info[0][visa_type][id]": visa_type_id,
            "info[0][visa_type][is_active]": 1,
            "info[0][visa_type][order]": visa_order,
            "info[0][visa_type][type_name]": visa_type_name,
            "info[0][web_id]": file1,
            "info[0][web_id_repeat]": file1,
            "selected_payment[grand_total]": "824",
            "selected_payment[link]": paymentlink,
            "selected_payment[name]": payment,
            "selected_payment[slug]": paymentslug,
            "resend": 0,
        }
        if file2:
            payload["selected_payment[grand_total]"] = "1648"
            # Adding the new info[1] parameters to the payload
            payload.update(
                {
                    "info[1][amountChangeData][allow_old_amount_until_new_date]": 2,
                    "info[1][amountChangeData][max_notification_count]": 0,
                    "info[1][amountChangeData][new_fees_applied_from]": "2018-08-05 00:00:00",
                    "info[1][amountChangeData][new_visa_fee]": 800.00,
                    "info[1][amountChangeData][notice]": "false",
                    "info[1][amountChangeData][notice_popup]": "",
                    "info[1][amountChangeData][notice_short]": "",
                    "info[1][amountChangeData][old_visa_fees]": 800.00,
                    "info[1][amount]": 800.00,
                    "info[1][captcha]": "",
                    "info[1][center][c_name]": center_name,
                    "info[1][center][id]": center_id,
                    "info[1][center][is_delete]": 0,
                    "info[1][center][prefix]": center_prefix,
                    "info[1][confirm_tos]": "true",
                    "info[1][email]": email,
                    "info[1][is_open]": "false",
                    "info[1][ivac][address]": ivac_address,
                    "info[1][ivac][allow_old_amount_until_new_date]": 2,
                    "info[1][ivac][app_key]": ivac_app_key,
                    "info[1][ivac][ceated_on]": "2018-07-12 05:58:00",
                    "info[1][ivac][center_info_id]": ivac_center_info_id,
                    "info[1][ivac][charge]": 3,
                    "info[1][ivac][contact_number]": "",
                    "info[1][ivac][created_at]": "2018-07-12 00:00:00",
                    "info[1][ivac][id]": ivac_id,
                    "info[1][ivac][is_delete]": 0,
                    "info[1][ivac][ivac_name]": ivac_ivac_name,
                    "info[1][ivac][max_notification_count]": 2,
                    "info[1][ivac][new_fees_applied_from]": "2018-08-05 00:00:00",
                    "info[1][ivac][new_visa_fee]": 800.00,
                    "info[1][ivac][notification_text_beside_amount]": "(From <from> this IVAC fees will be <new_amount> BDT)",
                    "info[1][ivac][notification_text_popup]": "",
                    "info[1][ivac][notify_fees_from]": "2018-07-29 04:54:32",
                    "info[1][ivac][old_visa_fee]": 800.00,
                    "info[1][ivac][prefix]": "D",
                    "info[1][ivac][visa_fee]": 800.00,
                    "info[1][name]": name2,
                    "info[1][passport]": "",
                    "info[1][phone]": phone,
                    "info[1][visa_type][$hashKey]": "object:50",
                    "info[1][visa_type][id]": visa_type_id,
                    "info[1][visa_type][is_active]": 1,
                    "info[1][visa_type][order]": visa_order,
                    "info[1][visa_type][type_name]": visa_type_name,
                    "info[1][web_id]": file2,
                    "info[1][web_id_repeat]": file2,
                }
            )

        if file3:
            payload["selected_payment[grand_total]"] = "2472"
            # Adding the new info[2] parameters to the payload
            payload.update(
                {
                    "info[2][amountChangeData][allow_old_amount_until_new_date]": 2,
                    "info[2][amountChangeData][max_notification_count]": 0,
                    "info[2][amountChangeData][new_fees_applied_from]": "2018-08-05 00:00:00",
                    "info[2][amountChangeData][new_visa_fee]": 800.00,
                    "info[2][amountChangeData][notice]": "false",
                    "info[2][amountChangeData][notice_popup]": "",
                    "info[2][amountChangeData][notice_short]": "",
                    "info[2][amountChangeData][old_visa_fees]": 800.00,
                    "info[2][amount]": 800.00,
                    "info[2][captcha]": "",
                    "info[2][center][c_name]": center_name,
                    "info[2][center][id]": center_id,
                    "info[2][center][is_delete]": 0,
                    "info[2][center][prefix]": center_prefix,
                    "info[2][confirm_tos]": "true",
                    "info[2][email]": email,
                    "info[2][is_open]": "false",
                    "info[2][ivac][address]": ivac_address,
                    "info[2][ivac][allow_old_amount_until_new_date]": 2,
                    "info[2][ivac][app_key]": ivac_app_key,
                    "info[2][ivac][ceated_on]": "2018-07-12 05:58:00",
                    "info[2][ivac][center_info_id]": ivac_center_info_id,
                    "info[2][ivac][charge]": 3,
                    "info[2][ivac][contact_number]": "",
                    "info[2][ivac][created_at]": "2018-07-12 00:00:00",
                    "info[2][ivac][id]": ivac_id,
                    "info[2][ivac][is_delete]": 0,
                    "info[2][ivac][ivac_name]": ivac_ivac_name,
                    "info[2][ivac][max_notification_count]": 2,
                    "info[2][ivac][new_fees_applied_from]": "2018-08-05 00:00:00",
                    "info[2][ivac][new_visa_fee]": 800.00,
                    "info[2][ivac][notification_text_beside_amount]": "(From <from> this IVAC fees will be <new_amount> BDT)",
                    "info[2][ivac][notification_text_popup]": "",
                    "info[2][ivac][notify_fees_from]": "2018-07-29 04:54:32",
                    "info[2][ivac][old_visa_fee]": 800.00,
                    "info[2][ivac][prefix]": "D",
                    "info[2][ivac][visa_fee]": 800.00,
                    "info[2][name]": name3,
                    "info[2][passport]": "",
                    "info[2][phone]": phone,
                    "info[2][visa_type][$hashKey]": "object:50",
                    "info[2][visa_type][id]": visa_type_id,
                    "info[2][visa_type][is_active]": 1,
                    "info[2][visa_type][order]": visa_order,
                    "info[2][visa_type][type_name]": visa_type_name,
                    "info[2][web_id]": file3,
                    "info[2][web_id_repeat]": file3,
                }
            )

        headers = {
            "Host": "payment.ivacbd.com",
            "User-Agent": "PostmanRuntime/7.42.0",
            "Connection": "keep-alive",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8;",
            "Cookie": f"XSRF-TOKEN={xsrf_token}; ivac_session={ivac_session}",
            # "Proxy-Authorization": f"Basic {encoded_auth}",
        }

        conn2 = http.client.HTTPSConnection("monthly-boss-polliwog.ngrok-free.app")
        conn2.request("POST", f"/reset_otp/{phone}")
        res2 = conn2.getresponse()
        data2 = res2.read()

        target_host = "payment.ivacbd.com"
        target_path = "/queue-manage"
        proxy_auth = f"{PROXY_USER}:{PROXY_PASS}"
        encoded_auth = base64.b64encode(proxy_auth.encode("utf-8")).decode("utf-8")

        try:
            while process[file1]["running"]:
                try:
                    # payload["hash_params_otp"] = getCaptchaToken()
                    conn = http.client.HTTPSConnection(PROXY_HOST, PROXY_PORT)
                    headers["Proxy-Authorization"] = f"Basic {encoded_auth}"
                    conn.set_tunnel(
                        target_host,
                        headers={"Proxy-Authorization": f"Basic {encoded_auth}"},
                    )
                    conn.request("POST", target_path, urlencode(payload), headers)
                    response = conn.getresponse()
                    print(f"File: ")
                    body = response.read().decode("utf-8")

                    if response.status != 504:
                        print(f"{body}")
                        # Parse the body as JSON
                        response_data = json.loads(body)
                        # Retrieve the 'code' from the response
                        code = response_data.get("code", None)
                        message = response_data.get("message", None)
                        # code = 200
                        # zsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhnzsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhnzsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhnzsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhn
                        if code:
                            process[file1]["status"] = message
                            print("Code:", code)
                            if code == "200" or code == 200:
                                break
                    else:
                        print("504 on sendOtp")
                        process[file1]["status"] = "504 on sendOtp"
                except:
                    print("No Json on sendOtp")
                    process[file1]["status"] = "No Json on sendOtp"
            while process[file1]["running"]:
                process[file1]["status"] = "Getting OTP"
                conn2 = http.client.HTTPSConnection(
                    "monthly-boss-polliwog.ngrok-free.app"
                )
                conn2.request("POST", f"/get_otp/{phone}")
                res2 = conn2.getresponse()
                data2 = res2.read()
                try:
                    response_json2 = json.loads(data2.decode("utf-8"))
                except json.JSONDecodeError:
                    print("Error: Response is not valid JSON at retriving OTP.")
                    print(f"Raw response data: {data2}")
                if res2.status != 404:
                    payload["otp"] = response_json2.get("otp")
                    print(f"OTP achieved for instance :{payload['otp']}")
                    payload["info[0][otp]"] = response_json2.get("otp")
                    payload["action"] = "verifyOtp"
                    break
                else:
                    print("OTP Processing.")
            while process[file1]["running"]:
                process[file1]["status"] = "Verifying OTP"
                try:
                    conn.request(
                        "POST",
                        target_path,
                        urlencode(payload),
                        headers,
                    )
                    response = conn.getresponse()
                    print(f"Verifying OTP: ")
                    if response.status != 504:
                        body = response.read().decode("utf-8")
                        print(body)
                        # Parse the body as JSON
                        response_data = json.loads(body)
                        # Retrieve the 'code' from the response
                        code = response_data.get("code", None)

                        # code = 200
                        if code:
                            print("Code:", code)
                            # zsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhnzsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhnzsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhn
                            if code == "200" or code == 200:
                                message = response_data.get("message", None)
                                process[file1]["status"] = message
                                slot_dates = response_data.get("data", {}).get(
                                    "slot_dates", None
                                )
                                # slot_dates = ["2024-12-30"]
                                # zsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhnzsexrdcfrvtgybuhnujmk,zsxd zsexrdcfrvtgybuhnujmk,zsxdrcftvgbhnjmk,xdcfvgbhnzsexrdcfrvtgybuhnujmk,zsxd
                                if slot_dates:
                                    print(
                                        f"OTP Verified for file Slot Dates:",
                                        slot_dates,
                                    )
                                    payload["action"] = "generateSlotTime"
                                    payload["amount"] = "10.00"
                                    payload["ivac_id"] = ivac_id
                                    payload["visa_type"] = 2
                                    payload["specific_date"] = slot_dates[0]
                                    payload["info[0][appointment_time]"] = slot_dates[0]
                                    break
                                else:
                                    print(f"Slot Date not found for file: ")
                                    process[file1]["status"] = "Slot Date not found"
                        else:
                            print(f"Code was not found at veifyOtp for file: ")
                    else:
                        print("504 on VerifyOtp")
                        process[file1]["status"] = "504 on VerifyOtp"
                except:
                    print(f"Response was not Json at VerifyOtp for file: ")
                    process[file1][
                        "status"
                    ] = "Response was not Json at VerifyOtp for file: "

            while process[file1]["running"]:
                process[file1]["status"] = "Getting Slot Times"
                try:
                    conn.request(
                        "POST",
                        "/get_payment_options_v2",
                        urlencode(payload),
                        headers,
                    )
                    response = conn.getresponse()
                    print(f"Getting Slot Times")
                    if response.status != 504:
                        body = response.read().decode("utf-8")
                        print(body)

                        # Parse the body as JSON
                        response_data = json.loads(body)
                        # Retrieve the 'code' from the response
                        status = response_data.get(
                            "status",
                            None,
                        )
                        # status = "OK"
                        # fddsfsdfgsfysfdgsfdgyfsgfyusfuysdyyvsyfgyufegfusfguysgfyus
                        if status == "OK":
                            slot_times = response_data.get("slot_times")
                            # fddsfsdfgsfysfdgsfdgyfsgfyusfuysdyyvsyfgyufegfusfguysgfyus
                            # slot_times = [
                            # {
                            # "id": 1,
                            # "hour": "10:00",
                            ##"ivac_id": 17,
                            # "visa_type": 13,
                            # "availableSlot": 1,
                            # "time_display": "10:00 AM",
                            # }
                            # ]
                            # fddsfsdfgsfysfdgsfdgyfsgfyusfuysdyyvsyfgyufegfusfguysgfyus
                            print(f"Slot Times for index :{slot_times}")
                            if len(slot_times) > 0:
                                payload["action"] = "payInvoice"
                                payload["selected_slot[id]"] = slot_times[0]["id"]
                                payload["info[0][slot_id]"] = slot_times[0]["id"]
                                payload["selected_slot[ivac_id]"] = slot_times[0][
                                    "ivac_id"
                                ]
                                payload["selected_slot[visa_type]"] = slot_times[0][
                                    "visa_type"
                                ]
                                payload["selected_slot[hour]"] = slot_times[0]["hour"]
                                payload["selected_slot[date]"] = slot_times[0]["date"]
                                payload["selected_slot[availableSlot]"] = slot_times[0][
                                    "availableSlot"
                                ]
                                payload["selected_slot[time_display]"] = slot_times[0][
                                    "time_display"
                                ]
                                payload["info[0][appointment_time]"] = slot_times[0][
                                    "hour"
                                ]

                                break
                            else:
                                print("Available slot Booked..!! Attempt number 2..!!")
                                continue
                        else:
                            print(f"Status not OK for file")
                            process[file1]["status"] = "Status not OK for file"
                except json.JSONDecodeError:
                    print("Failed to parse JSON response on generateSlotTimes.")

            while process[file1]["running"]:
                try:
                    process[file1]["status"] = "Attempting Slot Paying"
                    payload["hash_params"] = getCaptchaToken()
                    conn.request(
                        "POST",
                        "/slot_pay_now",
                        urlencode(payload),
                        headers,
                    )
                    response = conn.getresponse()
                    if response.status != 504:
                        body = response.read().decode("utf-8")
                        print(body)
                        # Parse the body as JSON
                        response_data = json.loads(body)
                        # Retrieve the 'code' from the response
                        status = response_data.get(
                            "status",
                            None,
                        )
                        if status:
                            print(
                                f"otp verified for file: ",
                                status,
                            )
                            if status == "OK":
                                print(f"attempting slot Paying: ")
                                url = response_data.get("url")
                                print(f"{url}{paymentslug}")
                                process[file1]["status"] = f"{url}{paymentslug}"
                                process[file1]["running"] = False
                                return {"Link": f"{url}{paymentslug}"}, 200
                                # conn5 = http.client.HTTPSConnection("api.sms.net.bd")
                                # conn5.request(
                                # "GET",
                                # f"/sendsms?api_key=31168cs9NJ69mW78jxoWA3Td4DdVTH1l5n3mdAmC&msg=Please%20Pay%20Here:%20{url}bkash&to={self.phone}",
                                # )
                                # res5 = conn.getresponse()
                                # data5 = res5.read()
                                # self.stop_flag = True
                                break

                    else:
                        print("Response was not in JSON format slot_pay_now..")
                        process[file1]["status"] = "504 on Slot Paying"
                except json.JSONDecodeError:
                    print("Failed to parse JSON response on slot_pay_now.")

        except Exception as e:
            print("Error", f"Instance Error: {e}")
        finally:
            conn.close()
        # Return a response

    threading.Thread(target=process_otp).start()
    return json.dumps({"status": "Processing SendOTP"}), 200


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run(port=3000, threaded=True, debug=True)
