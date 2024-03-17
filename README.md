# README

Read this code at your own risk, this is still work in progress😂

# Initalize a git repo

```
$ python3 main.py init test_repo

Initialized empty Git repository in test_repo
```

# Change directory

```
$ cd test_repo
```

# Create a new file

```
$ echo "Hell, World!" > greet.txt
```

# Check status

```
$ python3 ~/Documents/git-in-python/main.py status
On branch master


Untracked files:
    greet.txt

```

# Add file

```
$ python3 ~/Documents/git-in-python/main.py add greet.txt
```

# Commit file

```
$ python3 ~/Documents/git-in-python/main.py commit -m "Add greet.txt"
committed to master: 520b083f565d2335330eefe0cbd1f401abac600c
```
