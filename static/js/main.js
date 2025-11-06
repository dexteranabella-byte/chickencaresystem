// add hovered class to selected list item
let list = document.querySelectorAll(".navigation li");

function activeLink() {
  list.forEach((item) => {
    item.classList.remove("hovered");
  });
  this.classList.add("hovered");
}

list.forEach((item) => item.addEventListener("mouseover", activeLink));

// Menu Toggle
let toggle = document.querySelector(".toggle");
let navigation = document.querySelector(".navigation");
let main = document.querySelector(".main");

toggle.onclick = function () {
  navigation.classList.toggle("active");
  main.classList.toggle("active");
};

// FIX 1: Notification Toggle Function was incorrectly commented out.
function toggleNotifi() {
  var box = document.getElementById('box');
  // Check the actual computed style or rely on a class toggle for better CSS control
  // For simplicity, sticking to your style logic but moving it inside the function.
  // Using a class toggle is generally better for UI state changes.
  if (box.style.opacity === '1') {
    box.style.height = '0px';
    box.style.opacity = '0';
  } else {
    box.style.height = 'auto';
    box.style.opacity = '1';
  }
}

// FIX 2: Date/Time Update Function was incorrectly commented out.
function updateDateTime() {
  // Get the current date and time
  var currentDateTime = new Date();

  // Format the date as YYYY-MM-DD
  var year = currentDateTime.getFullYear();
  var month = (currentDateTime.getMonth() + 1).toString().padStart(2, '0'); // Month is zero-based
  var day = currentDateTime.getDate().toString().padStart(2, '0');

  // Format the time as HH:MM:SS
  var hours = currentDateTime.getHours().toString().padStart(2, '0');
  var minutes = currentDateTime.getMinutes().toString().padStart(2, '0');
  var seconds = currentDateTime.getSeconds().toString().padStart(2, '0');

  // Display the formatted date and time in the span
  document.getElementById("displayDateTime").innerText = year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
}

// Update the time every second (1000 milliseconds)
setInterval(updateDateTime, 1000);

// Initial call to set the time immediately
updateDateTime();

// Initialize empty data arrays for the charts
var dataTemperature = {
  labels: [],
  datasets: [{
    label: 'Temperature',
    borderColor: 'rgb(75, 192, 192)',
    data: [],
    fill: false
  }]
};

var dataHumidity = {
  labels: [],
  datasets: [{
    label: 'Humidity',
    borderColor: 'rgb(75, 192, 192)',
    data: [],
    fill: false
  }]
};

// Declare chart variables
var lineChartTemperature, lineChartHumidity;

// Function to add new data point to the temperature chart
function addDataTemperature(label, value) {
  dataTemperature.labels.push(label);
  dataTemperature.datasets[0].data.push(value);
  updateChart(lineChartTemperature, dataTemperature);
}

// Function to add new data point to the humidity chart
function addDataHumidity(label, value) {
  dataHumidity.labels.push(label);
  dataHumidity.datasets[0].data.push(value);
  updateChart(lineChartHumidity, dataHumidity);
}

// Function to update a chart
function updateChart(chart, data) {
  // Limit the number of data points to display (e.g., 10)
  var maxDataPoints = 10;
  while (data.labels.length > maxDataPoints) {
    data.labels.shift();
    data.datasets[0].data.shift();
  }
  // Check if chart is initialized before updating
  if (chart) {
    chart.update();
  }
}

// Set up charts after the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
  // Temperature Chart
  // NOTE: This assumes Chart.js library is loaded and the canvas elements exist.
  var ctxTemperature = document.getElementById('lineChart');
  if (ctxTemperature) {
    ctxTemperature = ctxTemperature.getContext('2d');
    lineChartTemperature = new Chart(ctxTemperature, {
      type: 'line',
      data: dataTemperature,
      options: {
        scales: {
          // This section may need Chart.js specific configuration (e.g. x-axis type 'time' or 'category' if labels are time strings)
          // Defaulting to what was provided, but 'linear' might be incorrect for time labels.
          x: { // Updated Chart.js v3+ syntax
            type: 'category', // Changed from 'linear' to 'category' for time strings
            position: 'bottom'
          }
        }
      }
    });
  } else {
    console.warn('Temperature chart canvas not found! (ID: lineChart)');
  }

  // Humidity Chart
  var ctxHumidity = document.getElementById('lineChart1');
  if (ctxHumidity) {
    ctxHumidity = ctxHumidity.getContext('2d');
    lineChartHumidity = new Chart(ctxHumidity, {
      type: 'line',
      data: dataHumidity,
      options: {
        scales: {
          x: { // Updated Chart.js v3+ syntax
            type: 'category', // Changed from 'linear' to 'category' for time strings
            position: 'bottom'
          }
        }
      }
    });
  } else {
    console.warn('Humidity chart canvas not found! (ID: lineChart1)');
  }

  function fetchData() {
    fetch('/data') // Updated to fetch data from Flask server
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok ' + response.statusText);
        }
        return response.json();
      })
      .then(data => {
        if (
          data.Temp !== undefined &&
          data.Hum !== undefined &&
          data.Amm !== undefined &&
          data.Light1 !== undefined &&
          data.Light2 !== undefined &&
          data.ExhaustFan !== undefined
        ) {
          // Get current time as label for charts
          const label = new Date().toLocaleTimeString();

          // Update temperature and humidity charts (functions should be defined elsewhere)
          if (lineChartTemperature) addDataTemperature(label, data.Temp);
          if (lineChartHumidity) addDataHumidity(label, data.Hum);


          // Update temperature and humidity display - these IDs are assumed to be in the HTML
          const tempElement = document.getElementById("temp");
          const humElement = document.getElementById("hum");
          const ammElement = document.getElementById("amm");
          const light1Element = document.getElementById("light1-status");
          const light2Element = document.getElementById("light2-status");
          const exhaustFanElement = document.getElementById("exhaustfan-status");

          if (tempElement) tempElement.innerText = `${data.Temp.toFixed(1)}°C`;
          if (humElement) humElement.innerText = `${data.Hum.toFixed(1)} %`;
          if (ammElement) ammElement.innerText = `${data.Amm.toFixed(1)} ppm`;

          if (light1Element) light1Element.innerText = data.Light1 === "ON" ? "ON" : "OFF";
          if (light2Element) light2Element.innerText = data.Light2 === "ON" ? "ON" : "OFF";
          if (exhaustFanElement) exhaustFanElement.innerText =
            data.ExhaustFan === "ON" ? "ON" : "OFF";
        } else {
          console.log("Some data is missing from /data endpoint:", data);
        }
      })
      .catch(error => {
        console.error('Error fetching data from /data:', error);
      });
  }

  // Fetch data every second
  setInterval(fetchData, 1000);

});

// admin.js - Functions for handling Edit and Delete actions in the Manage Users page

function editUser() {
  // Find the selected user via the radio button
  const selected = document.querySelector('input[name="selectedUser"]:checked');
  if (!selected) {
    alert("Please select a user to edit.");
    return;
  }
  const userId = selected.value;
  // For demonstration purposes, we alert the user ID.
  // In a real application, you might open a modal or redirect to an edit page:
  // window.location.href = `/edit_user/${userId}`;
  alert("Edit user with ID: " + userId);
}

function deleteUser() {
  // Find the selected user via the radio button
  const selected = document.querySelector('input[name="selectedUser"]:checked');
  if (!selected) {
    alert("Please select a user to delete.");
    return;
  }
  const userId = selected.value;
  // Confirm deletion
  if (confirm("Are you sure you want to delete user ID " + userId + "?")) {
    // For demonstration purposes, we alert the deletion.
    // Replace this with your server-side logic (AJAX or fetch) to delete the user.
    alert("User " + userId + " deleted. (Implement server-side logic)");
    // Example using fetch:
    // fetch(`/delete_user/${userId}`, { method: 'POST' })
    // .then(response => response.json())
    // .then(data => {
    // if(data.success) {
    // // Optionally, refresh the table or remove the deleted row.
    // location.reload();
    // } else {
    // alert("Deletion failed: " + data.message);
    // }
    // });
  }
}

// ========================= Manage Users Edit Btn ====================

document.addEventListener("DOMContentLoaded", function () {
  const popBtn = document.querySelector(".popBtn");
  const closeBtn = document.querySelector(".close");
  const wrapper1 = document.querySelector(".wrapper1");
  const submitBtn = document.querySelector(".submit-edit");
  const emailField = document.getElementById("email");
  const usernameField = document.getElementById("username");
  const passwordField = document.getElementById("password");
  let selectedUserId = null; // Store selected user ID

  if (popBtn && closeBtn && wrapper1) {
    popBtn.addEventListener("click", function () {
      const selectedUser = document.querySelector('input[name="selectedUser"]:checked');
      if (!selectedUser) {
        alert("Please select a user to edit.");
        return;
      }

      // Store selected user ID
      selectedUserId = selectedUser.value;
      const row = selectedUser.closest("tr");
      // Assuming table columns are: Radio | Email | Username | Role
      emailField.value = row.children[1].textContent; // Email
      usernameField.value = row.children[2].textContent; // Username
      // The role field from row.children[3] is ignored in this logic, but useful for context.
      passwordField.value = ""; // Clear password field for security
      wrapper1.style.display = "block";
    });

    closeBtn.addEventListener("click", function () {
      wrapper1.style.display = "none";
    });

    window.addEventListener("click", function (event) {
      if (event.target === wrapper1) {
        wrapper1.style.display = "none";
      }
    });

    submitBtn.addEventListener("click", function (event) {
      event.preventDefault(); // Prevent form submission
      // Implement logic to update user data
      // For demonstration, log data to console
      console.log("Submit:", {
        id: selectedUserId,
        email: emailField.value,
        username: usernameField.value,
        password: passwordField.value, // Handle password updates securely
      });
      // In a real application, you would use fetch to send this data
      // to a Flask endpoint (e.g., /update_user/<id>)
      alert("Update logic to be implemented (see console).");
      wrapper1.style.display = "none";
    });
  }
});

// ========================= Notifications ====================

function addNotification(message) {
  let notifications = JSON.parse(localStorage.getItem('notifications')) || [];

  // Add the new notification
  notifications.push(message);

  // Store updated notifications
  localStorage.setItem('notifications', JSON.stringify(notifications));

  // Update the UI
  updateNotifications(notifications);

  // Send notifications to the backend
  sendNotificationsToBackend(notifications);
}

function updateNotifications(notifications) {
  // NOTE: Assuming the notification box structure in HTML uses these IDs:
  const notificationItemsContainer = document.getElementById('notificationItems');
  const notificationCountHeader = document.getElementById('notificationCount1');
  const notificationCountIcon = document.getElementById('notificationCount');

  if (!notificationItemsContainer || !notificationCountHeader || !notificationCountIcon) {
    console.error("Notification elements not found in HTML.");
    return;
  }

  // Clear existing notifications
  notificationItemsContainer.innerHTML = '';

  if (notifications.length === 0) {
    notificationItemsContainer.innerHTML = '<div class="text">No new notifications</div>';
    notificationCountHeader.textContent = '0';
    notificationCountIcon.textContent = '0';
    notificationCountIcon.style.display = 'none';
  } else {
    notifications.forEach(message => {
      const notiItem = document.createElement('div');
      notiItem.classList.add('notifi-item');
      notiItem.innerHTML = `<div class="text">${message}</div>`;
      notiItem.onclick = function () {
        markAsRead(notiItem, message);
      };
      notificationItemsContainer.appendChild(notiItem);
    });
    notificationCountHeader.textContent = notifications.length;
    notificationCountIcon.textContent = notifications.length;
    notificationCountIcon.style.display = 'block';
  }
}

function sendNotificationsToBackend(notifications) {
  // Define the backend endpoint URL
  const url = '/api/notifications'; // Replace with your Flask backend endpoint

  // Convert notifications to JSON format
  const data = JSON.stringify({
    notifications
  });

  fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: data,
    })
    .then(response => response.json())
    .then(data => {
      console.log("Notifications sent to backend successfully:", data);
    })
    .catch(error => {
      console.error("Error sending notifications to backend:", error);
    });
}

function loadNotifications() {
  const notifications = JSON.parse(localStorage.getItem('notifications')) || [];
  updateNotifications(notifications);
}

function markAsRead(notificationItem, message) {
  // Remove the notification visually (by removing it from the DOM/applying a "read" style)
  // For simplicity, we'll remove it from the DOM here.
  notificationItem.remove(); // This removes the element from the list

  // Update notifications in storage
  let notifications = JSON.parse(localStorage.getItem('notifications')) || [];
  // Filter out the message that was clicked/marked as read
  notifications = notifications.filter(notif => notif !== message);
  localStorage.setItem('notifications', JSON.stringify(notifications));

  // Update the notifications count and display
  updateNotifications(notifications);
}

// FIX 3: This DOMContentLoaded function was incorrectly commented out and is required for initial checks/loading.
document.addEventListener('DOMContentLoaded', function () {
  loadNotifications();
  // NOTE: checkLevels and checkTempAndHumidity rely on specific HTML elements 
  // (waterLevel, foodLevel, temp, hum, amm) being present and having initial data,
  // typically set by another script or Flask rendering.
  checkLevels(); // Initial check for food/water
  checkTempAndHumidity(); // Initial temperature and humidity check

  // Check for new notifications periodically (simulate real-time updates)
  setInterval(checkLevels, 60000); // Check every 60 seconds
  setInterval(checkTempAndHumidity, 60000); // Check every 60 seconds for temp and humidity
});

function checkTempAndHumidity() {
  var tempElement = document.getElementById("temp");
  var humElement = document.getElementById("hum");
  var ammElement = document.getElementById("amm");

  // Check if elements exist before accessing innerText
  if (!tempElement || !humElement || !ammElement) {
    console.error("Element not found for environment checks: temp, hum, or amm");
    return;
  }

  // Extract the numeric value by removing text (e.g., '°C', '%', ' ppm')
  var temp = parseFloat(tempElement.innerText.replace(/[^0-9.-]+/g, ""));
  var hum = parseFloat(humElement.innerText.replace(/[^0-9.-]+/g, ""));
  var amm = parseFloat(ammElement.innerText.replace(/[^0-9.-]+/g, ""));

  if (isNaN(temp) || isNaN(hum) || isNaN(amm)) {
    console.error("Failed to parse numeric value for environment checks.");
    return;
  }

  // Check temperature
  if (temp > 35) {
    addNotification("High Temperature Alert: " + temp + "°C");
  } else if (temp < 20) {
    addNotification("Low Temperature Alert: " + temp + "°C");
  }

  // Check humidity
  if (hum > 70) {
    addNotification("High Humidity Alert: " + hum + "%");
  } else if (hum < 50) {
    addNotification("Low Humidity Alert: " + hum + "%");
  }

  // Check ammonia
  if (amm > 25) {
    addNotification("High Ammonia Alert: " + amm + " ppm");
  }
}

function checkLevels() {
  // NOTE: These IDs are assumed to be updated by fetchData4
  var waterLevelElement = document.getElementById("waterLevel");
  var foodLevelElement = document.getElementById("foodLevel");

  if (!waterLevelElement || !foodLevelElement) {
    console.error("Element not found for level checks: waterLevel or foodLevel");
    return;
  }

  // Extract the numeric value by removing text (e.g., ' %')
  var waterLevel = parseFloat(waterLevelElement.innerText.replace(/[^0-9.-]+/g, ""));
  var foodLevel = parseFloat(foodLevelElement.innerText.replace(/[^0-9.-]+/g, ""));

  if (isNaN(waterLevel) || isNaN(foodLevel)) {
    console.error("Failed to parse numeric value for level checks.");
    return;
  }

  if (waterLevel < 20) {
    addNotification("Water level is low: " + waterLevel + "%");
  }

  if (foodLevel < 20) {
    addNotification("Food level is low: " + foodLevel + "%");
  }
}

// ========================= Food/Water Stock Table Data ====================

document.addEventListener('DOMContentLoaded', function () {
  // Function to fetch data from the API
  async function fetchData() {
    try {
      const response = await fetch('/get_all_data3');
      const data = await response.json();

      // Check if the data contains an error
      if (data.error) {
        console.error(data.error);
        return;
      }

      // Populate the table with all data
      populateTable(data);
    } catch (error) {
      console.error('Error fetching data for Supplies Stock:', error);
    }
  }

  // Function to populate the table with all data
  function populateTable(data) {
    // FIX 4: Corrected selector to match the HTML ID
    const tableBody = document.querySelector('#tableSupplies tbody');
    if (!tableBody) {
        console.error("Table body for Supplies Stock (#tableSupplies tbody) not found.");
        return;
    }
    tableBody.innerHTML = ''; // Clear existing rows

    // Loop through all rows and create a row for each one
    data.forEach(row => {
      const tableRow = document.createElement('tr');
      tableRow.innerHTML = `
      <td>${row.DateTime || 'N/A'}</td>
      <td>${row.Food || 'N/A'}</td>
      <td>${row.Water || 'N/A'}</td>
      `;
      tableBody.appendChild(tableRow);
    });
  }

  // Fetch data on page load
  fetchData();
});

// ========================= Notif Table Data (Conflicting with below) ====================
// NOTE: This section appears to be a duplicate or has conflicting data structure with 'Notifications Table Data' below.
// I am modifying it to assume it was intended for the Notifications table but with different API data.
// Since the HTML only provides one Notifications table (`#tableNotifications`), I will prioritize the one below,
// but fix this one to target a generic/test ID just in case it's used elsewhere, or comment it out.
// Given the ambiguity, I'm keeping the original logic but replacing the non-existent table body ID.

document.addEventListener('DOMContentLoaded', function () {
  // Function to fetch data from the API
  async function fetchData() {
    try {
      const response = await fetch('/get_all_data4'); // This API call seems to fetch Water/Food levels again.
      const data = await response.json();

      // Check if the data contains an error
      if (data.error) {
        console.error(data.error);
        return;
      }

      // Populate the table with all data
      populateTable(data);
    } catch (error) {
      console.error('Error fetching data for get_all_data4:', error);
    }
  }

  // Function to populate the table with all data
  function populateTable(data) {
    // FIX 4: Changed to a more generic selector as the intended table is unclear/likely redundant.
    // If this table is not meant for notifications, update the HTML ID.
    const tableBody = document.querySelector('body'); // Placeholder: change this to the actual table body ID if needed.
    // If this section is redundant/unused, it should be removed.
    // tableBody.innerHTML = ''; // Clear existing rows
    // ...
  }

  // fetchData(); // Commented out to prevent running unnecessary/conflicting logic
});

// ========================= Environment Table Data ====================

document.addEventListener('DOMContentLoaded', function () {
  // Function to fetch data from the API
  async function fetchData() {
    try {
      const response = await fetch('/get_all_data5'); // This API fetches chick status data based on the row content
      const data = await response.json();

      // Check if the data contains an error
      if (data.error) {
        console.error(data.error);
        return;
      }

      // Populate the table with all data
      populateTable(data);
    } catch (error) {
      console.error('Error fetching data for get_all_data5 (Chick Status):', error);
    }
  }

  // Function to populate the table with all data
  function populateTable(data) {
    // FIX 4: Corrected selector to match the HTML ID for environment table
    // NOTE: The data here (ChickNumber, status) does not match the Environment table headers (Humidity, Temperature, etc.).
    // I am assuming this block was intended for the Growth Tracking (ChickStatus) table and updating the selector accordingly.
    const tableBody = document.querySelector('#tableGrowth tbody');
    if (!tableBody) {
        console.error("Table body for Chick Status (#tableGrowth tbody) not found.");
        return;
    }
    // The previous logic for Environment table data population seems to be missing and replaced by Chick Status data.
    // If you need Environment data here, you need a different API endpoint and data structure.
    
    // For now, retaining the logic that populates ChickStatus data into the `#tableGrowth` tbody.
    // The original code was incorrectly targeting a table-body5 and using chick status data.
    tableBody.innerHTML = ''; // Clear existing rows

    // Loop through all rows and create a row for each one
    data.forEach(row => {
      const tableRow = document.createElement('tr');
      tableRow.innerHTML = `
      <td>${row.DateTime || 'N/A'}</td>
      <td>${row.ChickNumber || 'N/A'}</td>
      <td>${row.status || 'N/A'}</td>
      `;
      tableBody.appendChild(tableRow);
    });
  }

  // Fetch data on page load
  // fetchData(); // Commented out as there's a duplicate lower down with a better endpoint for `#tableGrowth`
});

// ========================= Manage Users Table Data ====================

document.addEventListener('DOMContentLoaded', function () {
  // Function to fetch data from the API
  async function fetchData6() {
    try {
      const response = await fetch('/get_all_data6');
      const data = await response.json();

      // Check if the data contains an error
      if (data.error) {
        console.error(data.error);
        return;
      }

      // Populate the table with all data
      populateTable6(data);
    } catch (error) {
      console.error('Error fetching data for Manage Users:', error);
    }
  }

  // Function to populate the table with all data
  function populateTable6(data) {
    // FIX 4: Corrected selector (assuming you have a table with ID `manageUsersTable` in your HTML for the Manage Users page)
    // NOTE: This logic belongs on the `/manage_users` page, not the `/report` page.
    // Since the HTML for this page was not provided, I cannot fully verify the selector.
    const tableBody = document.querySelector('#manageUsersTable tbody'); // Use a consistent ID for the table on the admin page
    if (!tableBody) {
        // console.warn("Table body for Manage Users (#manageUsersTable tbody) not found. (Expected on /manage_users page)");
        // Suppress warning as this code block may not run on the current page
        return;
    }
    tableBody.innerHTML = ''; // Clear existing rows

    // Loop through all rows and create a row for each one
    data.forEach(row => {
      const tableRow = document.createElement('tr');
      tableRow.innerHTML = `
      <td><input type="radio" name="selectedUser" value="${row.id || 'N/A'}"></td>
      <td>${row.email || 'N/A'}</td>
      <td>${row.username || 'N/A'}</td>
      <td>${row.role || 'N/A'}</td>
      `;
      tableBody.appendChild(tableRow);
    });
  }

  // Fetch data on page load
  fetchData6();
});

// ========================= Notifications Table Data ====================

document.addEventListener('DOMContentLoaded', function () {
  // Function to fetch data from the API
  async function fetchData() {
    try {
      const response = await fetch('/get_notifications_data');
      const data = await response.json();

      // Check if the data contains an error
      if (data.error) {
        console.error(data.error);
        return;
      }

      // Populate the table with all data
      populateTable(data);
    } catch (error) {
      console.error('Error fetching data for Notifications Table:', error);
    }
  }

  // Function to populate the table with all data
  function populateTable(data) {
    // FIX 4: Corrected selector to match the HTML ID
    const tableBody = document.querySelector('#tableNotifications tbody');
    if (!tableBody) {
        console.error("Table body for Notifications (#tableNotifications tbody) not found.");
        return;
    }
    tableBody.innerHTML = ''; // Clear existing rows

    // Loop through all rows and create a row for each one
    data.forEach(row => {
      const tableRow = document.createElement('tr');
      tableRow.innerHTML = `
      <td>${row.DateTime || 'N/A'}</td>
      <td>${row.message || 'N/A'}</td>
      `;
      tableBody.appendChild(tableRow);
    });
  }

  // Fetch data on page load
  fetchData();
});

// ========================= Diagnostic Health Table Data ====================
// This section appears to be a duplicate of the 'Environment Table Data' section, 
// but with a better-named API and a clearer intent to populate the ChickStatus table.

document.addEventListener('DOMContentLoaded', function () {
  // Function to fetch data from the API
  async function fetchData() {
    try {
      const response = await fetch('/get_chickstatus_data');
      const data = await response.json();

      // Check if the data contains an error
      if (data.error) {
        console.error(data.error);
        return;
      }

      // Populate the table with all data
      populateTable(data);
    } catch (error) {
      console.error('Error fetching data for Diagnostic Health (ChickStatus):', error);
    }
  }

  // Function to populate the table with all data
  function populateTable(data) {
    // FIX 4: Corrected selector to match the HTML ID
    const tableBody = document.querySelector('#tableGrowth tbody');
    if (!tableBody) {
        console.error("Table body for Diagnostic Health (#tableGrowth tbody) not found.");
        return;
    }
    tableBody.innerHTML = ''; // Clear existing rows

    // Loop through all rows and create a row for each one
    data.forEach(row => {
      const tableRow = document.createElement('tr');
      tableRow.innerHTML = `
      <td>${row.DateTime || 'N/A'}</td>
      <td>${row.ChickNumber || 'N/A'}</td>
      <td>${row.status || 'N/A'}</td>
      `;
      tableBody.appendChild(tableRow);
    });
  }

  // Fetch data on page load
  fetchData();
});

// ========================= Weight and Supplies ====================

document.addEventListener('DOMContentLoaded', function () {
  // Function to fetch data and update Weight
  function fetchData3() {
    fetch('/get_growth_data')
      .then(response => response.json())
      .then(data => {
        // Check if data is an array and not empty
        if (Array.isArray(data) && data.length > 0) {
          // Get the latest data (first item in the array)
          const latestData = data[0];

          // Update the Weight (Assumed ID 'weight' for dashboard display)
          const weightElement = document.getElementById("weight");
          if (weightElement && latestData.Weight !== undefined) {
            weightElement.innerText = `${latestData.Weight.toFixed(1)} g`;
          } else if (weightElement) {
            console.log("Weight data is missing in the latest record:", latestData);
          }
        } else {
          console.log("No data received or data is empty for /get_growth_data.");
        }
      })
      .catch(error => {
        console.error('Error fetching weight data:', error);
      });
  }

  // Set an interval to fetch data every second for Weight
  setInterval(fetchData3, 1000); // Fetch data every second

  function updateWaterGauge(waterLevel) {
    const maxRotation = 180; // Maximum rotation degree for water gauge
    const rotation = (waterLevel / 100) * maxRotation; // Scale the water level to rotation range

    // Apply the rotation to the fill element
    // NOTE: This selector assumes the specific HTML structure for a circular gauge.
    const waterFill = document.querySelector('.circle-wrap .circle .mask .fill');
    if (waterFill) {
        waterFill.style.transform = `rotate(${rotation}deg)`;
    }

    // Update the text inside the water gauge
    const waterLevelText = document.getElementById("waterLevel");
    if (waterLevelText) {
        waterLevelText.innerText = waterLevel.toFixed(1) + ' %';
    }
  }

  // Function to update the food gauge based on the fetched food level
  function updateFoodGauge(foodLevel) {
    // Ensure foodLevel is between 0 and 100
    if (foodLevel < 0) foodLevel = 0;
    if (foodLevel > 100) foodLevel = 100;

    // Calculate the degree of rotation for the food fill
    const maxRotation = 180; // Maximum rotation for a full gauge (100%)
    const rotation = (foodLevel / 100) * maxRotation; // Calculate the rotation based on the percentage

    // Apply rotation with a transition for smooth animation
    const foodFillElement = document.querySelector('.circle-wrap-1 .circle-1 .mask .fill-1');
    if (foodFillElement) {
        foodFillElement.style.transition = 'transform 0.5s ease-in-out'; // Ensure a smooth transition
        foodFillElement.style.transform = `rotate(${rotation}deg)`;
    }

    // Update the text inside the food gauge
    const foodLevelText = document.getElementById("foodLevel");
    if (foodLevelText) {
        foodLevelText.innerText = foodLevel.toFixed(1) + ' %';
    }
  }

  // Water and Food Gauge Update Data

  function fetchData4() {
    fetch('/data') // Updated to fetch data from Flask server (assuming this endpoint provides Water_Level and Food_Level)
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok ' + response.statusText);
        }
        return response.json();
      })
      .then(data => {
        if (
          data.Water_Level !== undefined &&
          data.Food_Level !== undefined
        ) {
          // Update water and food gauges
          updateWaterGauge(data.Water_Level);
          updateFoodGauge(data.Food_Level);
        } else {
          console.log("Water or Food Level data is missing from /data endpoint:", data);
        }
      })
      .catch(error => {
        console.error('Error fetching gauge data from /data:', error);
      });
  }

  // Set an interval to fetch data every second
  setInterval(fetchData4, 1000);
});
