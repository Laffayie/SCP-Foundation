document.addEventListener("DOMContentLoaded", () => {
  const theme = "{{ session.get('theme', 'dark') }}";
  if (theme === "dark") {
    document.documentElement.classList.add("dark");
  }

  // Sidebar toggle
  const sidebar = document.querySelector(".sidebar");
  const content = document.querySelector(".content-shift");
  const toggleBtn = document.querySelector(".toggle-btn");
  const navItems = document.querySelectorAll(".nav-item span");

  if (!toggleBtn) {
    console.error("Toggle button not found!");
    return;
  }

  toggleBtn.addEventListener("click", () => {
    sidebar.classList.toggle("collapsed");
    sidebar.classList.toggle("expanded");
    content.classList.toggle("collapsed");
    content.classList.toggle("expanded");
    navItems.forEach((item) => {
      if (sidebar.classList.contains("collapsed")) {
        item.style.opacity = "0";
        item.style.display = "none";
      } else {
        item.style.opacity = "1";
        item.style.display = "inline";
      }
    });
  });

  // Toast notification handler

  // Theme handling
  const themeSelect = document.getElementById("theme");
  if (themeSelect) {
    themeSelect.addEventListener("change", function () {
      document.body.className = this.value;
    });
  }

  // Initialize Bootstrap (if included)
  if (typeof bootstrap !== "undefined") {
    const tooltipTriggerList = [
      ...document.querySelectorAll('[data-bs-toggle="tooltip"]'),
    ];
    tooltipTriggerList.map(
      (tooltipTriggerEl) => new bootstrap.Tooltip(tooltipTriggerEl)
    );

    const popoverTriggerList = [
      ...document.querySelectorAll('[data-bs-toggle="popover"]'),
    ];
    popoverTriggerList.map(
      (popoverTriggerEl) => new bootstrap.Popover(popoverTriggerEl)
    );
  } else {
    console.warn(
      "Bootstrap JS not loaded. Tooltips and popovers will not work."
    );
  }

  // Handle task status updates
  const statusButtons = document.querySelectorAll(".status-update");
  statusButtons.forEach((button) => {
    button.addEventListener("click", function () {
      const taskId = this.dataset.taskId;
      const newStatus = this.dataset.status;
      updateTaskStatus(taskId, newStatus);
    });
  });

  // static/js/main.js
  document.addEventListener("DOMContentLoaded", () => {
    // Existing code for dynamic updates (if any)
    // ... (keeping the previous fetch code for dashboard, SCPs, tasks, users)

    // Function to show toast notification
    function showToast(message, category) {
      // Create toast element
      const toast = document.createElement("div");
      toast.className = `fixed top-4 right-4 p-4 rounded-lg glass-effect border animate-fade-in max-w-sm z-50 transition-all duration-300`;

      // Style based on category
      if (category === "error") {
        toast.classList.add(
          "bg-red-500/20",
          "text-red-400",
          "border-red-500/30"
        );
      } else if (category === "success") {
        toast.classList.add(
          "bg-green-500/20",
          "text-green-400",
          "border-green-500/30"
        );
      } else {
        toast.classList.add(
          "bg-blue-500/20",
          "text-blue-400",
          "border-blue-500/30"
        );
      }

      // Add message
      toast.textContent = message;

      // Add close button
      const closeButton = document.createElement("button");
      closeButton.className = "absolute top-2 right-2 text-sm hover:text-white";
      closeButton.innerHTML = '<i class="fas fa-times"></i>';
      closeButton.onclick = () => toast.remove();
      toast.appendChild(closeButton);

      // Append to body
      document.body.appendChild(toast);

      // Auto-dismiss after 5 seconds
      setTimeout(() => {
        toast.classList.add("opacity-0");
        setTimeout(() => toast.remove(), 300);
      }, 5000);
    }

    // Expose showToast globally for Jinja2 calls
    window.showToast = showToast;

    // Existing fetch code for dynamic updates
    fetch("/dashboard")
      .then((response) => response.json())
      .then((data) => {
        // Update stats
        document.getElementById("totalScps").textContent = data.scps.length;
        document.getElementById("totalScientists").textContent =
          data.scientist_count;
        document.getElementById("totalSecurity").textContent =
          data.security_count;
        document.getElementById("totalTasks").textContent = data.task_count;

        // Update recent activities
        const activitiesContainer = document.getElementById("recentActivities");
        activitiesContainer.innerHTML = data.activities
          .map(
            (activity) => `
              <div class="flex items-center justify-between border-b border-muted pb-2">
                  <span>${activity.username}: ${activity.action}</span>
                  <span class="text-sm text-muted-foreground">${activity.timestamp}</span>
              </div>
          `
          )
          .join("");

        // Update SCP class stats
        const classStatsContainer = document.getElementById("scpClassStats");
        classStatsContainer.innerHTML = data.class_stats
          .map(
            (stat) => `
              <div class="flex justify-between">
                  <span>${stat.class}</span>
                  <span>${stat.count}</span>
              </div>
          `
          )
          .join("");

        // Update containment stats
        const containmentStatsContainer =
          document.getElementById("containmentStats");
        containmentStatsContainer.innerHTML = data.status_stats
          .map(
            (stat) => `
              <div class="flex justify-between">
                  <span>${stat.containment_status}</span>
                  <span>${stat.count}</span>
              </div>
          `
          )
          .join("");
      });

    // Fetch SCPs for manage-scps section
    if (document.getElementById("scpTableBody")) {
      fetch("/scp")
        .then((response) => response.json())
        .then((data) => {
          const scpTableBody = document.getElementById("scpTableBody");
          scpTableBody.innerHTML = data.scps
            .map(
              (scp) => `
                  <tr class="border-b border-muted">
                      <td class="p-4"><a href="/scp/profile/${
                        scp.scp_id
                      }" class="text-blue-400 hover:underline">${
                scp.scp_id
              }</a></td>
                      <td class="p-4">${scp.class}</td>
                      <td class="p-4">${scp.containment_status}</td>
                      <td class="p-4">${scp.assigned_users || "None"}</td>
                      <td class="p-4">
                          ${
                            data.role === "O5"
                              ? `
                          <form action="/scp/delete/${scp.scp_id}" method="POST" class="inline">
                              <button type="submit" class="text-red-400 hover:text-red-600">
                                  <i class="fas fa-trash"></i>
                              </button>
                          </form>
                          `
                              : ""
                          }
                      </td>
                  </tr>
              `
            )
            .join("");
        });
    }

    // Fetch tasks for manage-tasks section
    if (document.getElementById("taskTableBody")) {
      fetch("/task")
        .then((response) => response.json())
        .then((data) => {
          const taskTableBody = document.getElementById("taskTableBody");
          taskTableBody.innerHTML = data.tasks
            .map(
              (task) => `
                  <tr class="border-b border-muted">
                      <td class="p-4"><a href="/task/profile/${
                        task.id
                      }" class="text-blue-400 hover:underline">${
                task.title
              }</a></td>
                      <td class="p-4">${task.username}</td>
                      <td class="p-4">${task.status}</td>
                      <td class="p-4">${task.created || "N/A"}</td>
                      <td class="p-4">
                          <a href="/task/profile/${
                            task.id
                          }" class="text-blue-400 hover:text-blue-600">
                              <i class="fas fa-edit"></i>
                          </a>
                      </td>
                  </tr>
              `
            )
            .join("");
        });
    }

    // Fetch users for manage-users section
    if (document.getElementById("userTableBody")) {
      fetch("/users")
        .then((response) => response.json())
        .then((data) => {
          const userTableBody = document.getElementById("userTableBody");
          userTableBody.innerHTML = data.users
            .map(
              (user) => `
                  <tr class="border-b border-muted">
                      <td class="p-4"><a href="/user/profile/${
                        user.id
                      }" class="text-blue-400 hover:underline">${
                user.username
              }</a></td>
                      <td class="p-4">${user.nickname}</td>
                      <td class="p-4">${user.role}</td>
                      <td class="p-4">${user.status || "Active"}</td>
                      <td class="p-4">
                          <a href="/user/profile/${
                            user.id
                          }" class="text-blue-400 hover:text-blue-600 mr-2">
                              <i class="fas fa-edit"></i>
                          </a>
                          <form action="/user/delete/${
                            user.id
                          }" method="POST" class="inline">
                              <button type="submit" class="text-red-400 hover:text-red-600">
                                  <i class="fas fa-trash"></i>
                              </button>
                          </form>
                      </td>
                  </tr>
              `
            )
            .join("");
        });
    }
  });

  // Handle SCP filtering
  const filterForm = document.getElementById("filterForm");
  if (filterForm) {
    filterForm.addEventListener("submit", function (e) {
      e.preventDefault();
      const formData = new FormData(this);
      const params = new URLSearchParams(formData);
      window.location.href = `${window.location.pathname}?${params.toString()}`;
    });
  }

  // Profile image preview
  const profileInput = document.querySelector(
    'input[type="file"][name="profile_image"]'
  );
  if (profileInput) {
    profileInput.addEventListener("change", (e) =>
      previewProfileImage(e.target)
    );
  }
});

// Task status update function
function updateTaskStatus(taskId, newStatus) {
  fetch(`/tasks/${taskId}/status`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": '{{ session.csrf_token if session.csrf_token else "" }}', // Add CSRF protection if implemented
    },
    body: JSON.stringify({ status: newStatus }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        const statusBadge = document.querySelector(
          `#task-${taskId} .status-badge`
        );
        if (statusBadge) {
          statusBadge.textContent = newStatus;
          statusBadge.className = `status-badge badge ${getStatusClass(
            newStatus
          )}`;
        }
        showToast("Task status updated successfully", "success");
      } else {
        showToast("Failed to update task status", "error");
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      showToast("An error occurred while updating task status", "error");
    });
}

// Helper function to get status badge class
function getStatusClass(status) {
  switch (status) {
    case "Completed":
      return "bg-success";
    case "In Progress":
      return "bg-warning";
    default:
      return "bg-secondary";
  }
}

// Alert function (replaced with toast for consistency)
function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${type} show`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 5000); // Increased to 5 seconds for alerts
}

// Profile image preview
function previewProfileImage(input) {
  if (input.files && input.files[0]) {
    const reader = new FileReader();
    reader.onload = function (e) {
      const preview = document.querySelector(".profile-image");
      if (preview) {
        preview.src = e.target.result;
      }
    };
    reader.readAsDataURL(input.files[0]);
  }
}

// Password validation
function validatePassword(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return (
    password.length >= minLength &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumbers &&
    hasSpecialChar
  );
}

// Form validation
function validateForm(form) {
  const password = form.querySelector('input[name="password"]'); // Changed to 'password' for consistency
  if (password && password.value) {
    if (!validatePassword(password.value)) {
      showToast(
        "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters",
        "error"
      );
      return false;
    }
  }
  return true;
}

// Add form submission validation
const forms = document.querySelectorAll("form");
forms.forEach((form) => {
  form.addEventListener("submit", function (e) {
    if (!validateForm(this)) {
      e.preventDefault();
    }
  });
});

// static/js/main.js
document.addEventListener("DOMContentLoaded", () => {
  // Fetch dashboard data (for non-O5 users, this could be adjusted)
  fetch("/dashboard")
    .then((response) => response.json())
    .then((data) => {
      // Update stats
      document.getElementById("totalScps").textContent = data.scps.length;
      document.getElementById("totalScientists").textContent =
        data.scientist_count;
      document.getElementById("totalSecurity").textContent =
        data.security_count;
      document.getElementById("totalTasks").textContent = data.task_count;

      // Update recent activities
      const activitiesContainer = document.getElementById("recentActivities");
      activitiesContainer.innerHTML = data.activities
        .map(
          (activity) => `
              <div class="flex items-center justify-between border-b border-muted pb-2">
                  <span>${activity.username}: ${activity.action}</span>
                  <span class="text-sm text-muted-foreground">${activity.timestamp}</span>
              </div>
          `
        )
        .join("");

      // Update SCP class stats
      const classStatsContainer = document.getElementById("scpClassStats");
      classStatsContainer.innerHTML = data.class_stats
        .map(
          (stat) => `
              <div class="flex justify-between">
                  <span>${stat.class}</span>
                  <span>${stat.count}</span>
              </div>
          `
        )
        .join("");

      // Update containment stats
      const containmentStatsContainer =
        document.getElementById("containmentStats");
      containmentStatsContainer.innerHTML = data.status_stats
        .map(
          (stat) => `
              <div class="flex justify-between">
                  <span>${stat.containment_status}</span>
                  <span>${stat.count}</span>
              </div>
          `
        )
        .join("");
    });

  // Fetch SCPs for manage-scps section
  if (document.getElementById("scpTableBody")) {
    fetch("/scp")
      .then((response) => response.json())
      .then((data) => {
        const scpTableBody = document.getElementById("scpTableBody");
        scpTableBody.innerHTML = data.scps
          .map(
            (scp) => `
                  <tr class="border-b border-muted">
                      <td class="p-4"><a href="/scp/profile/${
                        scp.scp_id
                      }" class="text-blue-400 hover:underline">${
              scp.scp_id
            }</a></td>
                      <td class="p-4">${scp.class}</td>
                      <td class="p-4">${scp.containment_status}</td>
                      <td class="p-4">${scp.assigned_users || "None"}</td>
                      <td class="p-4">
                          ${
                            data.role === "O5"
                              ? `
                          <form action="/scp/delete/${scp.scp_id}" method="POST" class="inline">
                              <button type="submit" class="text-red-400 hover:text-red-600">
                                  <i class="fas fa-trash"></i>
                              </button>
                          </form>
                          `
                              : ""
                          }
                      </td>
                  </tr>
              `
          )
          .join("");
      });
  }

  // Fetch tasks for manage-tasks section
  if (document.getElementById("taskTableBody")) {
    fetch("/task")
      .then((response) => response.json())
      .then((data) => {
        const taskTableBody = document.getElementById("taskTableBody");
        taskTableBody.innerHTML = data.tasks
          .map(
            (task) => `
                  <tr class="border-b border-muted">
                      <td class="p-4"><a href="/task/profile/${
                        task.id
                      }" class="text-blue-400 hover:underline">${
              task.title
            }</a></td>
                      <td class="p-4">${task.username}</td>
                      <td class="p-4">${task.status}</td>
                      <td class="p-4">${task.created || "N/A"}</td>
                      <td class="p-4">
                          <a href="/task/profile/${
                            task.id
                          }" class="text-blue-400 hover:text-blue-600">
                              <i class="fas fa-edit"></i>
                          </a>
                      </td>
                  </tr>
              `
          )
          .join("");
      });
  }

  // Fetch users for manage-users section
  if (document.getElementById("userTableBody")) {
    fetch("/users")
      .then((response) => response.json())
      .then((data) => {
        const userTableBody = document.getElementById("userTableBody");
        userTableBody.innerHTML = data.users
          .map(
            (user) => `
                  <tr class="border-b border-muted">
                      <td class="p-4"><a href="/user/profile/${
                        user.id
                      }" class="text-blue-400 hover:underline">${
              user.username
            }</a></td>
                      <td class="p-4">${user.nickname}</td>
                      <td class="p-4">${user.role}</td>
                      <td class="p-4">${user.status || "Active"}</td>
                      <td class="p-4">
                          <a href="/user/profile/${
                            user.id
                          }" class="text-blue-400 hover:text-blue-600 mr-2">
                              <i class="fas fa-edit"></i>
                          </a>
                          <form action="/user/delete/${
                            user.id
                          }" method="POST" class="inline">
                              <button type="submit" class="text-red-400 hover:text-red-600">
                                  <i class="fas fa-trash"></i>
                              </button>
                          </form>
                      </td>
                  </tr>
              `
          )
          .join("");
      });
  }
});
