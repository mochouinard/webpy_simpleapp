Description:

This is a sample page that I used to learn WebPy.  It is not meant to be useful in product in it state.

It it a ultra basic ticket system with a login system.

NOTE: Modified version of webpy required.

Usage:
git clone https://github.com/mochouinard/webpy.git
ln -s webpy/web .
sqlite3 sample.db < db.sql
cp sample.ini local.ini
# Edit local.ini as needed
python server.py
