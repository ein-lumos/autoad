from storage import InMemoryStorage
from auth import register, login
from messages import send_message, view_inbox, view_sent, change_recipient
import os
import time

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    print(r"""⠀⠀⠀⠀
⠀.(`'`)-----(`'`)-----(`'`)-----(`'`)-----(`'`)-----(`'`).
 | '.'       '.'       '.'       '.'       '.'       '.' |
 |                                                       |
 |                 WELCOME TO VALENTINE!                 |
 |            Love is temporary. Flags are not.          |
 |                                                       |
 '(`'`)-----(`'`)-----(`'`)-----(`'`)-----(`'`)-----(`'`)'
   '.'       '.'       '.'       '.'       '.'       '.' """)


def user_menu(storage, user):
    while True:
        print(f"\nLogged in as: {user.username}")
        print("-" * 30)
        print("1. Send message")
        print("2. View inbox")
        print("3. View sent")
        print("4. Change recipient")
        print("5. Logout")

        choice = input("> ")

        if choice == "1":
            send_message(storage, user)
        elif choice == "2":
            view_inbox(storage, user)
        elif choice == "3":
            view_sent(storage, user)
        elif choice == "4":
            change_recipient(storage, user)
        elif choice == "5":
            break
        else:
            print("Invalid choice! Choose 1, 2, 3, 4 or 5")


def main_menu(storage):
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("> ")

        if choice == "1":
            register(storage)
        elif choice == "2":
            user = login(storage)
            if user:
                user_menu(storage, user)
        elif choice == "3":
            print("Goodbye! Hope your valentine reached the right hands! ")
            break
        else:
            print("Invalid choice! Choose 1, 2 or 3")


def main():
    storage = InMemoryStorage()

    clear()
    print_banner()
    time.sleep(0.5)

    main_menu(storage)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye! Hope your valentine reached the right hands!")
