# Blue Team Portal — Page Structure & Logic Prompt

Please generate the React pages and routing structure for our Blue Team Portal. This portal is used by SOC Analysts and SOC Managers to view scores, enter training rooms, and review reports.

The application is structured into three main logical folders/sections:

## 1. Dashboard & Frontend Logic (`/pages/dashboard/`)
This is the main landing area after a user logs in.

**Key Elements on this page:**
*   **User Greeting & Stats:** Display the user's name, role, and a quick summary of their overall average score across all past exercises.
*   **Past Reports (Recent History):** A section showing a list or grid of their all completed rooms. Each entry should show the scenario name, the date, their final score, and a button to "View Full Report".
*   **Enter a New Room CTA:** A prominent call-to-action button that navigates the user to the Room Lobby to find a new exercise.

## 2. Room Logic & Lobby (`/pages/rooms/`)
This section handles browsing and entering available training rooms.

**Key Elements on this page:**
*   **Available Rooms List:** A list or grid displaying all rooms currently available in the system.
*   **Room Details:** Each room item must show:
    *   The Scenario Name (e.g., "Ransomware Outbreak").
    *   The Room Status (Pending, Active, or Closed).
    *   A button to "Enter Room" (which should only be visually enabled if the room is 'Active').

## 3. Reporting Logic (`/pages/reports/`)
This is the most complex section. It displays post-incident reports, and the layout changes drastically based on the user's role.

### If the user is an **Analyst**:
*   They should only see their **own** individual report for the incident.
*   The page displays:
    *   Their overall Score and Grade.
    *   Metric breakdowns (e.g., Time to Detect, Time to Contain, Time to Respond).
    *   Skill progress bars (Detection, Containment, Recovery).
    *   A narrative text block containing feedback on their performance.

### If the user is a **SOC Manager**:
*   They see a **Team Overview** first.
*   The page displays:
    *   The overall Team Report (average score across all analysts in that room, overall time metrics).
    *   A list of all individual analysts who participated in that room.
    *   The manager can click on any specific analyst to expand and view that analyst's individual report (the same view the analyst sees above).

---
**Instructions for the AI:**
Please generate the React component code for these three main sections, including the conditional rendering logic required in the Reporting section to differentiate between an Analyst view and a Manager view. Use mock data to populate the interfaces so I can see how the layouts function.
