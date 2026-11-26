    } catch (err) {
        console.error("[FoodLink NGO Reminder Error]:", err.message);
        return { sent: false, error: err.message };
    } finally {
        isProcessingNgoReminder = false;
    }
}

// Note: Automatic 2-second interval timer disabled to prevent consuming email quota.
// Reminders are triggered only on explicit user events or manual admin action.

// Recurring reminder timer: checks on the configured schedule (default: 1 hour)
setInterval(() => {
    try {
        processHourlyReminderJob(false);
    } catch (e) {}
}, REMINDER_INTERVAL_MS);

// Continuous auto-expire timer: scans every 3 seconds in the background
setInterval(async () => {
    try {
        if (isSupabaseConfigured()) {
            await markExpired(getSupabase());
        }
    } catch (e) {}
}, 3000);

// ---------- Start Server ----------
if (require.main === module) {
    initDatabase()
        .then(function () {
            app.listen(PORT, function () {
                console.log("FoodLink running on port " + PORT);
            });
        })
        .catch(function (error) {
            console.error("[FoodLink] Warning: Database connection issue:", error.message);
            app.listen(PORT, function () {
                console.log("FoodLink running on port " + PORT + " (waiting for credentials)");
            });
        });
}

module.exports = app;
