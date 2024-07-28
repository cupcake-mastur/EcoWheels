class Stack:
    # Creates an empty stack.
    def __init__(self):
        self._theItems = list()

    # Returns True if the stack is empty or False
    # otherwise.
    def isEmpty(self):
        return len(self) == 0

    # Returns the number of items in the stack.
    def __len__ (self):
        return len(self._theItems)

    # Returns the top item on the stack without
    # removing it.
    def peek(self):
        if(self.isEmpty()):
            print("Cannot peek at an empty stack")
        else:
            return self._theItems[-1]
    
    # Removes and returns the top item on the stack.
    def pop(self):
        if(self.isEmpty()):
            print("Cannot pop from an empty stack")
        else:    
            return self._theItems.pop()
    
    # Push an item onto the top of the stack.
    def push(self, item):
        self._theItems.append(item)
        