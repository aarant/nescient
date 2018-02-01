# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/gui.py
""" Graphical User Interface (GUI) for Nescient. """
# TODO: Options, documentation, better path awareness, working directory changes, non-blocking benchmarking, About
import os
import glob
import webbrowser
from tkinter import Tk, Label, PhotoImage, OptionMenu, StringVar, Frame, Text, Scrollbar, RIGHT, Y, WORD, DISABLED, \
    Entry, Button, NORMAL, END, Menu, filedialog, Toplevel, messagebox, BooleanVar
from pkg_resources import Requirement, resource_filename
from threading import Thread, main_thread, current_thread

from nescient import __version__, url
from nescient.timing import load_benchmarks, estimate_time, TkTimer, benchmark_mode
from nescient.packer import DEFAULT_PACKING_MODE, PACKING_MODES, NescientPacker, PackingError
from nescient.process import start_packer_process

BANNER_PATH = resource_filename(Requirement.parse('Nescient'), os.path.join('nescient', 'resources', 'banner.gif'))
LOGO_PATH = resource_filename(Requirement.parse('Nescient'), os.path.join('nescient', 'resources', 'nessie.gif'))
MAIN_THREAD = main_thread()


# Frame containing all the packing modes and displays available benchmarks
class ModeSelectFrame(Frame):
    def __init__(self, master, default, modes):
        Frame.__init__(self, master)
        self.modes = modes
        self.update_rate_info()
        self.selected = StringVar(self)
        self.selected.set(default)
        self.label = Label(self, text='Packing mode:')
        self.options = OptionMenu(self, self.selected, *modes, command=self.display_rate_info)
        self.rate_info = Label(self)
        self.display_rate_info()
        self.label.grid(column=0, row=0)
        self.options.grid(column=1, row=0)
        self.rate_info.grid(column=2, row=0)

    def update_rate_info(self):
        benchmarks = load_benchmarks()
        self.rates = {}
        for mode in self.modes:
            if mode in benchmarks:
                times = benchmarks[mode]
                largest = sorted(times.keys())[-1]
                time = times[largest][-1]
                rate = round(largest / 2**20 / time, 1)
                self.rates[mode] = '(' + str(rate) + ' MiB/s)'
            else:
                self.rates[mode] = '(No benchmarks)'

    def display_rate_info(self, event=None):
        mode = self.selected.get()
        self.rate_info.config(text=self.rates[mode])


# Frame for adding arbitrary paths/wildcards
class PathSelectFrame:
    def __init__(self, master):
        self.label = Label(master, text='Path:')
        self.entry = Entry(master)
        self.button = Button(master, text='Add path(s)', command=lambda: master.add_files('glob'))
        self.label.grid(column=0, row=2, padx=5, pady=5, sticky='W')
        self.entry.grid(column=1, row=2, padx=5, pady=5, sticky='WE')
        self.button.grid(column=2, row=2, padx=5, pady=5, sticky='W')


# Text frame for displaying paths and errors
class OutputFrame(Frame):
    def __init__(self, master):
        Frame.__init__(self, master, bg='white')
        self.scroll = Scrollbar(self)
        self.scroll.pack(side=RIGHT, fill=Y)
        self.text = Text(self, fg='black', bg='white', wrap=WORD, yscrollcommand=self.scroll.set)
        self.text.config(height=8, width=16, padx=5, pady=5, state=DISABLED)
        self.text.pack(expand=True, fill='both')
        self.scroll.config(command=self.text.yview)

    def insert(self, text, *tags, index=END):
        self.text.config(state=NORMAL)
        self.text.insert(index, text, *tags)
        self.text.see('%s-2c' % index)
        self.text.config(state=DISABLED)

    def clear(self):
        self.text.config(state=NORMAL)
        self.text.delete(1.0, END)
        for tag in self.text.tag_names():
            self.text.tag_delete(tag)
        self.text.config(state=DISABLED)

    def see(self, *args):
        self.text.see(*args)

    def tag_config(self, *args, **kwargs):
        self.text.tag_config(*args, **kwargs)


# Frame for the pack, unpack, and clear files buttons
class ButtonFrame(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.pack = Button(self, text='Pack', command=lambda: master.pack_or_unpack('pack'))
        self.unpack = Button(self, text='Unpack', command=lambda: master.pack_or_unpack('unpack'))
        self.clear = Button(self, text='Clear files', command=master.clear_paths)
        self.pack.grid(column=0, row=0, padx=2)
        self.unpack.grid(column=1, row=0, padx=2)
        self.clear.grid(column=2, row=0, padx=2, sticky='E')


# The Menu
class NescientMenu(Menu):
    def __init__(self, master):
        Menu.__init__(self, master)
        self.add_command(label='Open', command=lambda: master.add_files('dialog'))
        self.option_menu = Menu(self, tearoff=0)
        self.option_menu.add_command(label='Benchmark current mode',
                                     command=lambda: master.threaded_task(master.benchmark_current_mode))
        self.option_menu.add_command(label='Benchmark all modes',
                                     command=lambda: master.threaded_task(master.benchmark_all_modes))
        self.option_menu.add_separator()
        self.overwrite = BooleanVar()
        self.overwrite.set(True)
        self.option_menu.add_checkbutton(label='Overwrite files', onvalue=True, offvalue=False, variable=self.overwrite)
        self.bring_to_front = BooleanVar()
        self.bring_to_front.set(True)
        self.option_menu.add_checkbutton(label='Bring to front', onvalue=True, offvalue=False,
                                         variable=self.bring_to_front)
        self.add_cascade(label='Options', menu=self.option_menu)
        self.add_command(label='About', command=lambda: AboutWindow(master))


# A Toplevel window for requesting passwords
class PasswordWindow(Toplevel):
    def __init__(self, master, success, failure):
        Toplevel.__init__(self, master)
        self.title('Password request')
        self.resizable(False, False)
        self.success = success
        self.failure = failure
        self.grab_set()
        self.focus_set()
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.bind('<Return>', self.test_submit)
        self.grid()
        self.label1 = Label(self, text='Insert password:')
        self.password = Entry(self, width=32, show='*')
        self.password.focus_set()
        self.label2 = Label(self, text='Verify password:')
        vcmd = self.register(self.can_submit)
        self.password2 = Entry(self, width=32, show='*', validate='key', validatecommand=(vcmd, '%P'))
        self.button = Button(self, text='Submit', state=DISABLED, command=lambda: self.close(self.password.get()))
        self.label1.grid(column=0, row=0, padx=5, pady=2)
        self.password.grid(column=1, row=0, padx=2, pady=2)
        self.label2.grid(column=0, row=1, padx=5, pady=2)
        self.password2.grid(column=1, row=1, padx=2, pady=2)
        self.button.grid(column=0, row=2, columnspan=2)

    def test_submit(self, *args):
        if self.button.cget('state') == NORMAL:
            self.close(self.password.get())

    def can_submit(self, password2):
        password = self.password.get()
        if password == password2 and password != '':
            self.button.config(state=NORMAL)
        else:
            self.button.config(state=DISABLED)
        return True

    def close(self, password=None):
        self.grab_release()
        self.master.grab_set()
        self.master.focus_force()
        if password:
            self.success(password)
        else:
            self.failure(password)
        self.destroy()


# A Toplevel window for displaying information about Nescient
class AboutWindow(Toplevel):
    def __init__(self, master):
        Toplevel.__init__(self, master)
        self.title('About Nescient')
        self.resizable(False, False)
        self.grab_set()
        self.focus_set()
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.logo_image = PhotoImage(file=LOGO_PATH)
        self.logo = Label(self, image=self.logo_image)
        self.label = Label(self, text='Copyright (c) 2018 Ariel Antonitis')
        self.url = Label(self, text=url, fg='#369a9d')
        self.url.bind('<Button-1>', lambda event: webbrowser.open(url))
        self.url.bind('<Enter>', lambda event: self.url.config(cursor='hand1'))
        self.url.bind('<Leave>', lambda event: self.url.config(cursor=''))
        self.logo.grid(column=0, row=0)
        self.label.grid(column=0, row=1, padx=10)
        self.url.grid(column=0, row=2, padx=10)

    def close(self):
        self.grab_release()
        self.master.grab_set()
        self.master.focus_force()
        self.destroy()
            

# The main UI
class NescientUI(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title('Nescient ' + __version__)
        try:
            self.tk.call('wm', 'iconphoto', self._w, PhotoImage(file=LOGO_PATH))
        except Exception:
            pass
        self.protocol('WM_DELETE_WINDOW', self.close)
        # Initialize widgets
        self.grid()
        self.menu = NescientMenu(self)
        self.configure(menu=self.menu)
        self.banner_image = PhotoImage(file=BANNER_PATH)
        self.banner = Label(self, image=self.banner_image)
        self.mode_select = ModeSelectFrame(self, DEFAULT_PACKING_MODE, PACKING_MODES)
        self.path_select = PathSelectFrame(self)
        self.text = OutputFrame(self)
        self.button_frame = ButtonFrame(self)
        self.status = Label(self, text='Ready.')
        # Set up the grid
        self.banner.grid(column=0, row=0, padx=0, ipadx=0, ipady=0, pady=0, sticky='N', columnspan=3)
        self.mode_select.grid(column=0, row=1, padx=5, pady=5, sticky='NW', columnspan=3)
        self.text.grid(column=0, row=3, padx=5, pady=5, sticky='NSEW', columnspan=3)
        self.button_frame.grid(column=0, row=4, padx=5, pady=5, sticky='NW', columnspan=3)
        self.status.grid(column=0, row=5, padx=5, pady=5, sticky='W', columnspan=3)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(1, weight=1)
        # Set up initial variables
        self.paths = []
        self.state = 'ready'
        self.open_dir = os.getcwd()

    def close(self):
        if self.state != 'ready':
            if messagebox.askyesno('Abort operation?', 'Nescient is currently working, closing it now may result in '
                                                       'lost or corrupted data. Close Nescient anyway?',
                                   icon=messagebox.WARNING):
                self.destroy()
        else:
            self.destroy()

    def global_widget_state(self, state):
        self.menu.entryconfig('Open', state=state)
        self.menu.entryconfig('Options', state=state)
        self.menu.entryconfig('About', state=state)
        self.mode_select.options.config(state=state)
        self.path_select.entry.config(state=state)
        self.path_select.button.config(state=state)
        self.button_frame.pack.config(state=state)
        self.button_frame.unpack.config(state=state)
        self.button_frame.clear.config(state=state)

    # Run a function on a new thread and freeze the UI until it finishes
    def threaded_task(self, func, *args, **kwargs):
        if current_thread() == MAIN_THREAD:
            Thread(target=lambda: self.threaded_task(func, *args, **kwargs), daemon=True).start()
            return
        self.global_widget_state(DISABLED)
        self.state = 'working'
        try:
            return_value = func(*args, **kwargs)
        except Exception as e:
            self.status.config(text=str(e))
            return_value = e
        self.global_widget_state(NORMAL)
        self.state = 'ready'
        return return_value

    def add_files(self, choice):
        self.status.config(text='Adding files...')
        if choice == 'glob':
            pattern = self.path_select.entry.get()
            paths = [path for path in glob.glob(pattern, recursive=True) if os.path.isfile(path)]
        else:  # choice == 'dialog':
            paths = list(filedialog.askopenfilenames(initialdir=self.open_dir, parent=self, title='Add files'))
            if paths:
                self.open_dir = os.path.dirname(paths[0])
        for path in paths:
            if not self.paths:
                self.text.clear()
            if path not in self.paths:
                self.text.insert(path + '\n', path.replace(' ', '?'))
                self.paths.append(path)
        self.status.config(text='Ready.')

    def clear_paths(self):
        self.status.config(text='Clearing paths...')
        self.paths = []
        self.text.clear()
        self.status.config(text='Ready')

    def pack_or_unpack(self, choice, password=None):
        # Retrive packer mode information
        alg, mode, auth = self.mode_select.selected.get().split('-', 2)
        if len(self.paths) == 0:
            self.status.config(text='No files specified.')
            self.clear_paths()
            return
        # Request password
        if password is None:
            PasswordWindow(self, success=lambda password: self.pack_or_unpack(choice, password),
                           failure=self.password_failed)
            return
        self.status.config(text='Password request successful.')
        # Build the packer, and start processing files
        packer = NescientPacker(password, alg, mode, auth)
        self.threaded_task(self.packing_loop, choice, packer)

    def password_failed(self, password):
        self.status.config(text='Password request failed.')
        
    def packing_loop(self, choice, packer):
        self.title('Nescient %s - %s' % (__version__, 'Packing' if choice == 'pack' else 'Unpacking'))
        for path in self.paths:
            try:
                # Color and scroll to the tag
                tag = path.replace(' ', '?')
                self.text.text.see('%s.first' % tag)
                self.text.tag_config(tag, background='#369a9d')
                # Fix the out path and set up display text
                file_out_path = NescientPacker.fix_out_path(path, None, choice)
                display_text = os.path.split(path)[1] + ' > ' + os.path.split(file_out_path)[1]
                # Determine estimated time
                if choice == 'pack':
                    packing_mode = packer.alg + '-' + packer.mode + '-' + packer.auth
                else:
                    parsed = NescientPacker.parse_nescient_header(path)
                    packing_mode = parsed['alg'] + '-' + parsed['mode'] + '-' + parsed['auth']
                est_time = estimate_time(os.path.getsize(path), packing_mode)
                # Set up the timer and packing process
                timer = TkTimer(self, display_text, est_time, lambda s: self.status.config(text=s))
                p, queue = start_packer_process(packer, path, file_out_path, choice,
                                                overwrite=self.menu.overwrite.get())
                timer.start()
                p.join()
                if queue.empty():
                    timer.stop()
                    self.text.tag_config(tag, background='#34c96c')
                    self.text.insert('...Completed!', tag, index='%s.last-1c' % tag)
                else:
                    timer.stop(error=True)
                    e = queue.get()
                    error_string = e.__class__.__name__ + ': ' + str(e)
                    self.status.config(text=error_string)
                    self.text.tag_config(tag, background='red')
                    self.text.insert(error_string + '\n', tag, index='%s.last' % tag)
            except PackingError as e:
                error_string = e.__class__.__name__ + ': ' + str(e)
                self.status.config(text=error_string)
                self.text.tag_config(tag, background='red')
                self.text.insert(error_string + '\n', tag, index='%s.last' % tag)
        self.paths = []
        self.status.config(text='All files processed.')
        self.title('Nescient ' + __version__)
        # Bring the window to the front, if specified
        if self.menu.bring_to_front.get():
            self.wm_state('normal')
            self.lift()
            self.focus_force()

    def benchmark_current_mode(self):
        packing_mode = self.mode_select.selected.get()
        self.status.config(text='Benchmarking...')
        self.title('Nescient ' + __version__ + ' - Benchmarking')
        benchmark_mode(packing_mode)
        self.mode_select.update_rate_info()
        self.mode_select.display_rate_info()
        self.status.config(text='Ready')
        self.title('Nescient ' + __version__)

    def benchmark_all_modes(self):
        self.title('Nescient ' + __version__ + ' - Benchmarking')
        for packing_mode in PACKING_MODES:
            self.status.config(text='Benchmarking ' + packing_mode + '...')
            benchmark_mode(packing_mode)
        self.mode_select.update_rate_info()
        self.mode_select.display_rate_info()
        self.status.config(text='Ready')
        self.title('Nescient ' + __version__)
                                

if __name__ == '__main__':
    gui = NescientUI()
    gui.mainloop()
