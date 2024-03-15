# mood-selection
Mood application for usiu africa


1. **Authentication Routes (`auth_blueprint`):**
    - `/auth/register`: User registration with username, password, email, name, and age.
    - `/auth/login`: User login with either username/password or a session token.
    - `/auth/register_anonymous`: Anonymous user registration.
    - `/auth/logout`: User logout (requires JWT authentication).
    - `/auth/refresh`: Refresh JWT access token.
    - `/security/anonymity-policy`: Retrieve the anonymity policy.
    - `/security/data-security-policy`: Retrieve the data security policy.
    - `/security/data-usage-policy`: Retrieve the data usage policy.

2. **Mood Routes (`mood_blueprint`):**
    - `/mood/aggregate`: Get aggregate class mood.
    - `/mood/explanations/add`: Add optional explanations for mood selections.
    - `/mood/explanations/list`: Retrieve explanations for mood selections.
    - `/mood/select`: Select and store user mood.
    - `/mood/track`: Retrieve mood data for the past 24 hours.
    - `/mood/list`: Retrieve all stored mood data.
    - `/mood/tracking/add`: Capture mood data at specific points during the lesson or at regular intervals.
    - `/mood/tracking/history`: Retrieve mood tracking history.
    - `/mood/engagement/activities`: Suggest activities or discussion topics based on the overall mood.
    - `/mood/engagement/positive-reinforcement`: Highlight positive moods with encouraging messages.
    - `/mood/engagement/motivational-quotes`: Display uplifting quotes based on the chosen mood.
    - `/mood/engagement/anonymous-polls`: Create and list anonymous polls.

3. **Insights Routes (`insights_blueprint`):**
    - `/insights/individual-tracking`: Retrieve individual tracking data (requires teacher role).
    - `/insights/mood-analysis`: Retrieve mood analysis data for the past 30 days.
    - `/insights/anonymous-feedback`: Submit anonymous feedback.
    - `/insights/class-climate`: Retrieve class climate data.
    - `/insights/mood`: Retrieve mood insights for the past 7 days.
    - `/insights/export`: Export mood data as a CSV file.



### Authentication APIs (`auth_blueprint`):

1. **User Registration:**
   - **Endpoint:** `/auth/register` (POST)
   - **Parameters:**
     - `username`: User's username
     - `password`: User's password
     - `email`: User's email
     - `name`: User's name
     - `age`: User's age
   - **Description:** Allows a user to register by providing necessary information. Validates input and checks for existing usernames.

2. **User Login:**
   - **Endpoint:** `/auth/login` (POST)
   - **Parameters:**
     - `username` (optional): User's username
     - `password` (optional): User's password
     - `session_token` (optional): Session token for authentication
   - **Description:** Authenticates users based on either username/password or session token. Generates access tokens for authenticated users.

3. **Anonymous User Registration:**
   - **Endpoint:** `/auth/register_anonymous` (POST)
   - **Description:** Allows the creation of anonymous users with unique usernames. Generates a session token for anonymous access.

4. **User Logout:**
   - **Endpoint:** `/auth/logout` (DELETE)
   - **Description:** Logs out the user by invalidating the access token. Requires a valid JWT token.

5. **Token Refresh:**
   - **Endpoint:** `/auth/refresh` (POST)
   - **Description:** Refreshes the user's access token using a refresh token. Requires a valid refresh token.





### Mood APIs (`mood_blueprint`):

1. **Select Mood:**
   - **Endpoint:** `/mood/select` (POST)
   - **Parameters:**
     - `mood`: Selected mood
   - **Description:** Allows users to select a mood. Stores the mood data in the database.

2. **Track Mood:**
   - **Endpoint:** `/mood/track` (GET)
   - **Description:** Retrieves mood data for the past 24 hours. Provides a history of mood selections.

3. **List Moods:**
   - **Endpoint:** `/mood/list` (GET)
   - **Description:** Retrieves all mood data stored in the database.

4. **Aggregate Mood:**
   - **Endpoint:** `/mood/aggregate` (GET)
   - **Description:** Retrieves aggregate class mood data for the past 30 days.

5. **Add Explanation:**
   - **Endpoint:** `/mood/explanations/add` (POST)
   - **Parameters:**
     - `explanation`: Optional explanation for a mood selection
   - **Description:** Allows users to add optional explanations for their mood selections.

6. **List Explanations:**
   - **Endpoint:** `/mood/explanations/list` (GET)
   - **Description:** Retrieves all explanations for mood selections stored in the database.

7. **Add Tracking:**
   - **Endpoint:** `/mood/tracking/add` (POST)
   - **Parameters:**
     - `mood`: Tracked mood
   - **Description:** Captures mood data at specific points during a lesson or at regular intervals throughout the day.

8. **Tracking History:**
   - **Endpoint:** `/mood/tracking/history` (GET)
   - **Description:** Retrieves mood tracking history data.

9. **Engagement Features:**
   - **Endpoints:**
     - `/mood/engagement/activities` (GET)
     - `/mood/engagement/positive-reinforcement` (GET)
     - `/mood/engagement/motivational-quotes` (GET)
     - `/mood/engagement/anonymous-polls` (GET, POST)
   - **Description:** Provides suggestions for activities, positive reinforcement, motivational quotes, and anonymous polls based on mood data.



   

### Insights APIs (`insights_blueprint`):

1. **Individual Tracking:**
   - **Endpoint:** `/insights/individual-tracking` (GET)
   - **Description:** Retrieves individual tracking data, e.g., mood data for the past 30 days.

2. **Mood Analysis:**
   - **Endpoint:** `/insights/mood-analysis` (GET)
   - **Description:** Retrieves mood analysis data, e.g., mood data for the past 30 days.

3. **Anonymous Feedback:**
   - **Endpoint:** `/insights/anonymous-feedback` (POST)
   - **Parameters:**
     - `feedback`: Anonymous feedback
   - **Description:** Allows users to submit anonymous feedback.

4. **Class Climate:**
   - **Endpoint:** `/insights/class-climate` (GET)
   - **Description:** Retrieves class climate data, e.g., mood data for the past 30 days.

5. **Mood Insights:**
   - **Endpoint:** `/insights/mood` (GET)
   - **Description:** Retrieves mood insights data, e.g., mood counts for the past 7 days.

6. **Export Insights:**
   - **Endpoint:** `/insights/export` (GET)
   - **Description:** Exports mood data to a CSV file for the past 30 days.

### Security APIs (`auth_blueprint`):

1. **Anonymity Policy:**
   - **Endpoint:** `/security/anonymity-policy` (GET)
   - **Description:** Retrieves the anonymity policy.

2. **Data Security Policy:**
   - **Endpoint:** `/security/data-security-policy` (GET)
   - **Description:** Retrieves the data security policy.

3. **Data Usage Policy:**
   - **Endpoint:** `/security/data-usage-policy` (GET)
   - **Description:** Retrieves the data usage policy.

### Error Handling:
   - Custom error handlers for various HTTP exceptions (Bad Request, Not Found, Unauthorized, Internal Server Error) and a generic exception handler.

Please note that the exact behavior of some functionalities may depend on the actual implementations of certain methods (e.g., `validate_session_token`).

