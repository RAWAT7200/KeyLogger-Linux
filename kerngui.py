import sys
from Tkinter import * 
from ttk import *
import time
m=Tk()
m.title("Kern-Gui")
m.geometry('1000x800')
tb1=Text(m,height=800,width=1000)
tb1.pack()

with open('/var/log/messages') as f:
	data=f.read()
	for line in data:
		tb1.insert(END,line)		
m.mainloop()


