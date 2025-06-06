document.addEventListener(
  "DOMContentLoaded",
  () => {
    // Theme Initialization
    const theme = "{{ session.get('theme', 'dark') }}";
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    }

    const themeSelect = document.getElementById("theme");
    if (themeSelect) {
      themeSelect.addEventListener("change", () => {
        document.body.className = themeSelect.value;
      });
    }

    // Sidebar Toggle
    const sidebar = document.querySelector(".sidebar");
    const content = document.querySelector(".content-shift");
    const toggleBtn = document.querySelector(".toggle-btn");
    const navItems = document.querySelectorAll(".nav-item span");

    if (toggleBtn) {
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
    } else {
      console.error("Toggle button not found!");
    }

    // Toast Notification Function
    function showToast(message, category = "info") {
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

      toast.textContent = message;

      const closeButton = document.createElement("button");
      closeButton.className = "absolute top-2 right-2 text-sm hover:text-white";
      closeButton.innerHTML = '<i class="fas fa-times"></i>';
      closeButton.onclick = () => toast.remove();
      toast.appendChild(closeButton);

      document.body.appendChild(toast);

      setTimeout(() => {
        toast.classList.add("opacity-0");
        setTimeout(() => toast.remove(), 300);
      }, 5000);
    }

    // Expose showToast globally for Jinja2 calls
    window.showToast = showToast;

    // Bootstrap Initialization (Tooltips and Popovers)
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

    // Task Status Update Handler
    const statusButtons = document.querySelectorAll(".status-update");
    statusButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const taskId = button.dataset.taskId;
        const newStatus = button.dataset.status;
        updateTaskStatus(taskId, newStatus);
      });
    });

    function updateTaskStatus(taskId, newStatus) {
      fetch(`/tasks/${taskId}/status`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken":
            '{{ session.csrf_token if session.csrf_token else "" }}',
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
          console.error("Error updating task status:", error);
          showToast("An error occurred while updating task status", "error");
        });
    }

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

    // Profile Image Preview
    const profileInput = document.querySelector(
      'input[type="file"][name="profile_image"]'
    );
    if (profileInput) {
      profileInput.addEventListener("change", (e) =>
        previewProfileImage(e.target)
      );
    }

    function previewProfileImage(input) {
      if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = (e) => {
          const preview = document.querySelector(".profile-image");
          if (preview) {
            preview.src = e.target.result;
          }
        };
        reader.readAsDataURL(input.files[0]);
      }
    }

    // Form Validation
    function validatePassword(password) {
      const minLength = 4;

      return password.length >= minLength;
    }

    function validateForm(form) {
      const password = form.querySelector('input[name="password"]');
      if (password && password.value) {
        if (!validatePassword(password.value)) {
          showToast("Password must be at least 4 characters", "error");
          return false;
        }
      }
      return true;
    }

    const forms = document.querySelectorAll("form");
    forms.forEach((form) => {
      form.addEventListener("submit", (e) => {
        if (!validateForm(form)) {
          e.preventDefault();
        }
      });
    });

    // SCP Filter Form
    const filterForm = document.getElementById("filterForm");
    if (filterForm) {
      filterForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const formData = new FormData(filterForm);
        const params = new URLSearchParams(formData);
        window.location.href = `${
          window.location.pathname
        }?${params.toString()}`;
      });
    }

    // Dynamic Data Fetching
    function fetchAndRender(url, containerId, renderFunction, errorMessage) {
      fetch(url)
        .then((response) => {
          if (!response.ok) throw new Error(`Failed to fetch data from ${url}`);
          return response.json();
        })
        .then((data) => {
          const container = document.getElementById(containerId);
          if (container) {
            container.innerHTML = renderFunction(data);
          }
        })
        .catch((error) => {
          console.error(errorMessage, error);
          showToast(errorMessage, "error");
        });
    }

    // Dashboard Data
    fetchAndRender(
      "/dashboard",
      null,
      (data) => {
        // Update stats
        document.getElementById("totalScps").textContent = data.scps.length;
        document.getElementById("totalScientists").textContent =
          data.scientist_count;
        document.getElementById("totalSecurity").textContent =
          data.security_count;
        document.getElementById("totalTasks").textContent = data.task_count;

        // Update recent activities
        const activitiesHtml = data.activities
          .map(
            (activity) => `
            <div class="flex items-center justify-between border-b border-muted pb-2">
                <span>${activity.username}: ${activity.action}</span>
                <span class="text-sm text-muted-foreground">${activity.timestamp}</span>
            </div>
          `
          )
          .join("");
        document.getElementById("recentActivities").innerHTML = activitiesHtml;

        const ctx = document.getElementById("scpClassChart");
        if (ctx) {
          new Chart(ctx, {
            type: "pie",
            data: {
              labels: data.class_stats.map((stat) => stat.class),
              datasets: [
                {
                  data: data.class_stats.map((stat) => stat.count),
                  backgroundColor: ["#3b82f6", "#10b981", "#ef4444"], // Blue, Green, Red
                  borderColor: ["#1e40af", "#065f46", "#b91c1c"],
                  borderWidth: 1,
                },
              ],
            },
            options: {
              responsive: true,
              plugins: {
                legend: { position: "top" },
                title: { display: true, text: "SCP Distribution by Class" },
              },
            },
          });
        }

        return "";
      },
      "Failed to load dashboard data"
    );

    // Update SCP class stats
    const classStatsHtml = data.class_stats
      .map(
        (stat) => `
            <div class="flex justify-between">
                <span>${stat.class}</span>
                <span>${stat.count}</span>
            </div>
          `
      )
      .join("");
    document.getElementById("scpClassStats").innerHTML = classStatsHtml;

    // Update containment stats
    const containmentStatsHtml = data.status_stats
      .map(
        (stat) => `
            <div class="flex justify-between">
                <span>${stat.containment_status}</span>
                <span>${stat.count}</span>
            </div>
          `
      )
      .join("");
    document.getElementById("containmentStats").innerHTML =
      containmentStatsHtml;

    return ""; // No direct container update for dashboard
  },
  "Failed to load dashboard data"
);

// SCPs Data
fetchAndRender(
  "/scp",
  "scpTableBody",
  (data) =>
    data.scps
      .map(
        (scp) => `
          <tr class="border-b border-muted">
              <td class="p-4"><a href="/scp/profile/${
                scp.scp_id
              }" class="text-blue-400 hover:underline">${scp.scp_id}</a></td>
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
      .join(""),
  "Failed to load SCP data"
);

// Tasks Data
fetchAndRender(
  "/task",
  "taskTableBody",
  (data) =>
    data.tasks
      .map(
        (task) => `
          <tr class="border-b border-muted">
              <td class="p-4"><a href="/task/profile/${
                task.id
              }" class="text-blue-400 hover:underline">${task.title}</a></td>
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
      .join(""),
  "Failed to load tasks data"
);

// Users Data
fetchAndRender(
  "/users",
  "userTableBody",
  (data) =>
    data.users
      .map(
        (user) => `
          <tr class="border-b border-muted">
              <td class="p-4"><a href="/user/profile/${
                user.id
              }" class="text-blue-400 hover:underline">${user.username}</a></td>
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
      .join(""),
  "Failed to load users data"
);

tailwind.config = {
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        border: "hsl(217.2 32.6% 17.5%)",
        input: "hsl(217.2 32.6% 17.5%)",
        ring: "hsl(212.7 26.8% 83.9%)",
        background: "hsl(222.2 84% 4.9%)",
        foreground: "hsl(210 40% 98%)",
        primary: {
          DEFAULT: "hsl(210 40% 98%)",
          foreground: "hsl(222.2 84% 4.9%)",
        },
        secondary: {
          DEFAULT: "hsl(217.2 32.6% 17.5%)",
          foreground: "hsl(210 40% 98%)",
        },
        destructive: {
          DEFAULT: "hsl(0 62.8% 30.6%)",
          foreground: "hsl(210 40% 98%)",
        },
        muted: {
          DEFAULT: "hsl(217.2 32.6% 17.5%)",
          foreground: "hsl(215 20.2% 65.1%)",
        },
        accent: {
          DEFAULT: "hsl(217.2 32.6% 17.5%)",
          foreground: "hsl(210 40% 98%)",
        },
        card: {
          DEFAULT: "hsl(222.2 84% 4.9%)",
          foreground: "hsl(210 40% 98%)",
        },
      },
      animation: {
        "fade-in": "fadeIn 0.5s ease-in-out",
        "slide-up": "slideUp 0.3s ease-out",
        "pulse-glow": "pulseGlow 2s infinite",
        "bounce-subtle": "bounceSubtle 1s ease-in-out",
        "spin-slow": "spin 3s linear infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        slideUp: {
          "0%": { transform: "translateY(100%)" },
          "100%": { transform: "translateY(0)" },
        },
        pulseGlow: {
          "0%, 100%": { boxShadow: "0 0 5px rgba(59, 130, 246, 0.5)" },
          "50%": { boxShadow: "0 0 20px rgba(59, 130, 246, 0.8)" },
        },
        bounceSubtle: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-5px)" },
        },
      },
    },
  },
};

function generateReport() {
  fetch("/generate_report", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then((response) => {
      if (!response.ok) {
        return response.json().then((err) => {
          throw new Error(err.message);
        });
      }
      return response.blob();
    })
    .then((blob) => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "SCP_Foundation_Report.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast("Report generated successfully!", "success");
    })
    .catch((error) => {
      console.error("Error:", error);
      showToast(`Failed to generate report: ${error.message}`, "error");
    });
}
