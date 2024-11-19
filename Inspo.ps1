# Define a list of inspirational messages

$Messages = @(

"Rise and shine! Today is a new opportunity to achieve greatness.",

"Believe in yourself. You are capable of amazing things.",

"Every morning is a chance to start fresh. Make today count!",

"Dream big, work hard, and stay positive.",

"Success is not final, failure is not fatal: It is the courage to continue that counts.",

"Be the energy you want to attract. Start your day with a smile!",

"You are stronger than you think and braver than you believe.",

"Wake up with determination. Go to bed with satisfaction.",

"The best way to predict the future is to create it.",

"Your only limit is your mind. Think positive and conquer the day!"

)


# Select a random message

$RandomMessage = Get-Random -InputObject $Messages


# Display the message

Write-Output "Good Morning! "

Write-Output "Inspirational Message of the Day:"

Write-Output "`n$RandomMessage"


# Optional: Display a toast notification (Windows 10/11+)

if (Get-Command -Name "New-BurntToastNotification" -ErrorAction SilentlyContinue) {

New-BurntToastNotification -Text "Good Morning! ", $RandomMessage

} else {

Write-Output "`nInstall the BurntToast module for notifications: Install-Module -Name BurntToast -Scope CurrentUser"

}
