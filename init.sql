-- Create schema if needed
CREATE TABLE IF NOT EXISTS matches (
    id SERIAL PRIMARY KEY,
    season INT,
    city VARCHAR(100),
    date DATE,
    team1 VARCHAR(100),
    team2 VARCHAR(100),
    toss_winner VARCHAR(100),
    toss_decision VARCHAR(50),
    result VARCHAR(50),
    dl_applied BOOLEAN,
    winner VARCHAR(100),
    win_by_runs INT,
    win_by_wickets INT,
    player_of_match VARCHAR(100),
    venue VARCHAR(200)
);

CREATE TABLE IF NOT EXISTS deliveries (
    id SERIAL PRIMARY KEY,
    match_id INT REFERENCES matches(id) ON DELETE CASCADE,
    inning INT,
    batting_team VARCHAR(100),
    bowling_team VARCHAR(100),
    over INT,
    ball INT,
    batsman VARCHAR(100),
    bowler VARCHAR(100),
    runs_batsman INT,
    runs_extras INT,
    total_runs INT,
    is_wicket BOOLEAN,
    dismissal_kind VARCHAR(100)
);

-- Sample IPL Matches Data
INSERT INTO matches (season, city, date, team1, team2, toss_winner, toss_decision, result, dl_applied, winner, win_by_runs, win_by_wickets, player_of_match, venue)
VALUES 
(2023, 'Mumbai', '2023-03-29', 'Mumbai Indians', 'Chennai Super Kings', 'Mumbai Indians', 'bat', 'normal', FALSE, 'Mumbai Indians', 20, 0, 'Rohit Sharma', 'Wankhede Stadium'),
(2023, 'Bangalore', '2023-03-30', 'Royal Challengers Bangalore', 'Delhi Capitals', 'Delhi Capitals', 'field', 'normal', FALSE, 'Delhi Capitals', 0, 7, 'David Warner', 'Chinnaswamy Stadium');

-- Sample IPL Deliveries Data
INSERT INTO deliveries (match_id, inning, batting_team, bowling_team, over, ball, batsman, bowler, runs_batsman, runs_extras, total_runs, is_wicket, dismissal_kind)
VALUES 
(1, 1, 'Mumbai Indians', 'Chennai Super Kings', 1, 1, 'Rohit Sharma', 'Deepak Chahar', 4, 0, 4, FALSE, NULL),
(1, 1, 'Mumbai Indians', 'Chennai Super Kings', 1, 2, 'Rohit Sharma', 'Deepak Chahar', 1, 0, 1, FALSE, NULL);
