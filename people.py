class People:
    def __init__(self, name):
        if not name:
            raise ValueError("Missing name")
        self.name = name

class Soldier(People):

    def __init__(self, name, rank):
        super().__init__(name)
        ranks = ["Private", "Corporal", "Sergeant", "Lieutenant", "Captain", "Major", "Colonel", "General"]
        if rank not in ranks:
            raise ValueError("Invalid rank")
        self.rank = rank
        


    def __str__(self):
        return (f"Name: {self.name}\nRank: {self.rank}")
