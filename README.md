**THESE SCRIPTS ARE FOR WINDOWS**

**PLEASE NOTE DELUGE SCRIPT IS NO LONGER ACTIVELY MAINTAINED**

Instructions:

    1. Download and install Python. There should be an option for "Add to PATH variables" during installation - make sure it is enabled

    2. Download the .py file of choice (or alternatively just copy the script into notepad and save it as a .py file)

    3. For the qbittorrent script update the VPN_EXE, QBIT_EXE, QBIT_CONFIG, and LOG_DIR variables at the beginning of the script to match the file paths on your system. Same for the deluge script variables if that is the one you want to use

    4. You can enable logging by setting LOGGING_ENABLED = True and configuring DEBUG_LOG_FILE to your path/file of choice

    5. Open Task Scheduler and then Create New Task. Set your triggers as needed (e.g. run when user logs on) and set up the action to run the .py script you downloaded. Most importantly, tick the "Run with elevated privileges" box - if you don't do this then some of the programs won't terminate properly and you will end up getting the same server and port every time

    6. Test the script out by running it from Task Scheduler.

    Hopefully it should just work, but if it doesn't work, you can open a command prompt with elevated privileges and run the script by typing e.g. C:/Users/<YourUsername>/Documents/proton_qbit_port_refresh.py. If the script crashes you will be able to see the output this way. If it doesn't execute at all then you have an issue with your Python PATH variables.
