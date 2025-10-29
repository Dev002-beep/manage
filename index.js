const functions = require('firebase-functions');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
admin.initializeApp();

// Scheduled function to disable expired accounts
exports.disableExpiredAccounts = functions.pubsub.schedule('every 1 hours').onRun(async (context) => {
    const now = Date.now();
    const usersRef = admin.database().ref('users');
    const usersSnapshot = await usersRef.once('value');
    const usersData = usersSnapshot.val();

    if (!usersData) {
        console.log('No users found.');
        return null;
    }

    const updates = {};
    let disabledCount = 0;

    for (const userId in usersData) {
        const user = usersData[userId];
        const disableTimestamp = user.disableTimestamp;

        // Check if the timestamp exists, is in the past, and the user is not already disabled
        if (disableTimestamp && disableTimestamp < now && (user.isDisabled === false || user.isDisabled === undefined)) {
            updates[`${userId}/isDisabled`] = true;
            disabledCount++;
        }
    }

    if (Object.keys(updates).length > 0) {
        try {
            await usersRef.update(updates);
            console.log(`Successfully disabled ${disabledCount} accounts.`);
            return {
                status: 'success',
                message: `Successfully disabled ${disabledCount} accounts.`
            };
        } catch (error) {
            console.error('Error auto-disabling accounts:', error);
            return {
                status: 'error',
                message: 'Error auto-disabling accounts.'
            };
        }
    } else {
        console.log('No accounts to disable.');
        return {
            status: 'info',
            message: 'No accounts to disable.'
        };
    }
});