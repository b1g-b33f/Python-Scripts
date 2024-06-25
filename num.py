with open('numbers.txt', 'w') as file:
    for i in range(1, 5000):
        file.write(f"{i}\n")
