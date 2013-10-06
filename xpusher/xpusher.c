/* Xpusher - send keyboard events to another's window
 * by:		Peter Shipley [copyright 1989]
 * compile:	cc -O xpusher.c -o xpusher -lX11
 * use:		xpusheR Windowid
 *	Windowid		in decimal
 *	-w Windowid		in decimal
 * 	-h Windowid		in hex
 * 	-d name_of_display
 *
 * see xwininfo(1) of xterm env. var. WINDOWID for window ID number
 */

#include <stdio.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#ifndef lint
char *copyright = "@(#) Copyright(c) 1988 Peter Shipley  [HACKMAN].\n\
    All rights reserved.\n";
#endif not lint

#define STRING	"X pusher"
void exit();

void usage(comm)
char *comm;
{
    (void) fprintf(stderr,
	"usage: %s ([-w] Windowid | -h 0xWindowid) [-d displayname]\n", comm);

    exit(1);
}
/*
 * This structure forms the WM_HINTS property of the window,
 * letting the window manager know how to handle this window.
 */
XWMHints	xwmh = {
    (InputHint|StateHint),	/* flags */
    True,			/* input */
    NormalState,		/* initial_state */
    0,				/* icon pixmap */
    0,				/* icon window */
    0, 0,			/* icon location */
    0,				/* icon mask */
    0,				/* Window group */
};

main(argc,argv)
    int argc;
    char **argv;
{
    char	*displayname = NULL;
    int		i;

    Display    *dpy = NULL;	/* X server connection */
    Window      rwin;		/* Recive Window ID */
    Window      swin;		/* Send Window ID */
    XSizeHints  xsh;		/* Size hints for window manager */


    /* parse the arguments (a but much for 3 options) */
    for (i = 1; i < argc; i++) {
	char *arg = argv[i];

	if (arg[0] == '-') {
	    switch (arg[1]) {
	      case 'd':			/* -display host:dpy */
		if (++i >= argc) usage (argv[0]);
		displayname = argv[i];
		continue;

	      case 'h':			/* -h WindowId_in_hex */
		if (++i >= argc) usage (argv[0]);
		swin = atoi(argv[i]);
		/* (void) sscanf(argv[i], "0x%lx", &swin); */
		continue;

	      case 'w':			/* -w WindowId_in_decimal */
		if (++i >= argc) usage (argv[0]);
		swin = atoi(argv[i]);
		continue;

	      default:
		usage (argv[0]);
	    }				/* end switch on - */
	} else 
	  swin = atoi(argv[i]);
    }					/* end for over argc */

    if(swin == (Window) NULL) usage (argv[0]);

    /* Open the display */
    if ((dpy = XOpenDisplay(displayname)) == NULL) {
	(void) fprintf(stderr, "%s: can't open %s\n",
			     argv[0], XDisplayName(displayname));
	exit(1);
    }

    /*
     * Deal with providing the window with an initial position & size.
     * Fill out the XSizeHints struct to inform the window manager.
     */
    xsh.flags = (PPosition|PSize);
    xsh.height = 72;
    xsh.width = 2* 72;
    xsh.x = (DisplayWidth(dpy, DefaultScreen(dpy)) - xsh.width) / 2;
    xsh.y = (DisplayHeight(dpy, DefaultScreen(dpy)) - xsh.height) / 2;

    /*
     * Create the Window with the information in the XSizeHints, the
     * border width,  and the border & background pixels. 
     */
    rwin = XCreateSimpleWindow(dpy, DefaultRootWindow(dpy),
			      xsh.x, xsh.y, xsh.width, xsh.height,
			      1,
			      WhitePixel(dpy, DefaultScreen(dpy)),
			      BlackPixel(dpy, DefaultScreen(dpy)));

    /* Set the standard properties for the window managers.  */
    XSetStandardProperties(dpy, rwin, STRING, STRING, None, argv, argc, &xsh);
    XSetWMHints(dpy, rwin, &xwmh);

    /* Specify the event types we're interested in - only Exposures.  */
    XSelectInput(dpy, rwin, FocusChangeMask|KeyPressMask|KeyReleaseMask);

    /* Map the window to make it visible. */
    XMapWindow(dpy, rwin);

    /* Loop forever,  examining each event.  */
    while (1) {
	XEvent      event;		/* Event received */
	/*
	 * Get the next event
	 */
	XNextEvent(dpy, &event);

	/* if event is a Key event forward it */
	if(event.type == KeyPress || event.type == KeyRelease) 
	    XSendEvent(dpy, swin, True, (KeyPressMask|KeyReleaseMask), &event);
    }
}
