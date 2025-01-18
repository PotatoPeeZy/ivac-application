document
  .getElementById("dataForm")
  .addEventListener("submit", async (event) => {
    event.preventDefault();

    const formData = new URLSearchParams({
      csrf_token: document.getElementById("csrf_token").value,
      xsrftoken: document.getElementById("xsrftoken").value,
      ivac_session: document.getElementById("ivac_session").value,
      email: document.getElementById("email").value,
      ivac_center: document.getElementById("ivac_center").value,
      phone: document.getElementById("phone").value,
      payment: document.getElementById("payment").value,
      visa: document.getElementById("visa").value,
    });

    // Add up to 3 name and fileID pairs to formData
    for (let i = 1; i <= 3; i++) {
      const name = document.getElementById(`name${i}`).value;
      const fileID = document.getElementById(`fileID${i}`).value;
      if (name && fileID) {
        formData.append(`name${i}`, name);
        formData.append(`fileID${i}`, fileID);
      }
    }

    const responseList = document.getElementById("responseList");
    const listItem = document.createElement("li");
    listItem.textContent = "Submitting data...";
    responseList.appendChild(listItem);

    try {
      const response = await fetch(sendOtpUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        listItem.textContent = `Response: ${JSON.stringify(data, null, 2)}`;
      } else {
        listItem.textContent = `Error: ${response.status} ${response.statusText}`;
      }
    } catch (error) {
      listItem.textContent = `Error: ${error.message}`;
    }
  });
