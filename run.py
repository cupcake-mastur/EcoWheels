# run to create tables in the database
from __init__ import create_app

app ,model = create_app()

if __name__ == "__main__":
    app.run(debug=True)
