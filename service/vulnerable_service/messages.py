from datetime import datetime

MAX_MESSAGE_LENGTH = 256

def send_message(storage, current_user):
    recipient_username = input("Recipient username: ").strip()
    text = input("Valentine text: ").strip()

    if len(text) == 0:
        print("Text of valentine cannot be empty!")
        return

    if len(text) > MAX_MESSAGE_LENGTH:
        print("Text of valentine too long (>256 characters)")
        return

    recipient = storage.get_user_by_username(recipient_username)

    if not recipient:
        print("Recipient not found!")
        return

    if recipient.id == current_user.id:
        print("You cannot send valentine to yourself!")
        return	
    # возможно это не нужно
    if storage.count_messages() >= 1000:
        print("Valentine's limit reached.")
        return

    message = storage.add_message(
        current_user.id,
        recipient.id,
        text
    )

    print(f"Valentine sent. ID: {message.id}")


def view_inbox(storage, current_user):
    inbox = storage.get_inbox(current_user.id)

    if not inbox:
        print("\n[!] Empty! You don't have any valentines.")
        return

    for msg in inbox:
        print("\n---")
        print(f"ID: {msg.id}")
        print(f"From: {storage.get_user_by_id(msg.sender_id).username}")
        print(f"Text: {msg.text}")
        print(f"Read: {msg.is_read}")

        storage.mark_as_read(msg.id)


def view_sent(storage, current_user):
    sent = storage.get_sent(current_user.id)

    if not sent:
        print("\n[!] Empty...Spread some love first!")
        return

    for msg in sent:
        print("\n---")
        print(f"ID: {msg.id}")
        print(f"To: {storage.get_user_by_id(msg.recipient_id).username}")
        print(f"Text: {msg.text}")
        print(f"Read: {msg.is_read}")


def change_recipient(storage, current_user):
    try:
        message_id = int(input("Valentine ID: ").strip())
    except ValueError:
        print("Invalid message ID!")
        return

    new_recipient_username = input("New recipient username: ").strip()

    message = storage.get_message(message_id)

    if not message:
        print("Valentine not found!")
        return

    # здесь можно впихнуть уязвимость
    if message.sender_id != current_user.id:
        print("Access denied!")
        return

    if message.is_read:
        print("Can't change recipient after reading!")
        return

    new_recipient = storage.get_user_by_username(new_recipient_username)

    if not new_recipient:
        print("User not found!")
        return

    if new_recipient.id == current_user.id:
        print("You can't sent valentine to yourself!")
        return

    storage.update_recipient(message.id, new_recipient.id)
    print("Recipient updated!")

