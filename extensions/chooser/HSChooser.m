//
//  HSChooser.m
//  Hammerspoon
//
//  Created by Chris Jones on 29/12/2015.
//  Copyright © 2015 Hammerspoon. All rights reserved.
//

#import "HSChooser.h"

#pragma mark - Chooser object implementation

@implementation HSChooser
- (id)initWithRows:(NSInteger)numRows width:(CGFloat)width fontName:(NSString *)fontName fontSize:(CGFloat)fontSize refTable:(int *)refTable {
    self = [super init];
    if (self) {
        self.refTable = refTable;
        self.numRows = numRows;
        self.width = width;
        self.fontName = fontName;
        self.fontSize = fontSize;

        self.currentStaticChoices = nil;
        self.currentCallbackChoices = nil;
        self.choicesCallbackRef = LUA_NOREF;
        self.queryChangedCallbackRef = LUA_NOREF;

        // Decide which font to use
        if (!self.fontName) {
            self.font = [NSFont systemFontOfSize:self.fontSize];
        } else {
            self.font = [NSFont fontWithName:self.fontName size:self.fontSize];
        }

        [self calculateRects];

        if (![self setupWindow]) {
            return nil;
        }
    }

    return self;
}

- (void)calculateRects {
    // Calculate the sizes of the various bits of our UI
    NSRect winRect, contentViewRect, textRect, listRect, dividerRect;

    winRect = NSMakeRect(0, 0, 100, 100);
    contentViewRect = NSInsetRect(winRect, 10, 10);

    NSDivideRect(contentViewRect, &textRect, &listRect, NSHeight([self.font boundingRectForFont]), NSMaxYEdge);
    NSDivideRect(listRect, &dividerRect, &listRect, 20.0, NSMaxYEdge);
    dividerRect.origin.y += NSHeight(dividerRect) / 2.0;
    dividerRect.size.height = 1.0;

    self.winRect = winRect;
    self.textRect = textRect;
    self.listRect = listRect;
    self.dividerRect = dividerRect;
}

- (BOOL)setupWindow {
    // Create and configure our window

    self.windowController = [[HSChooserWindowController alloc] initWithOwner:self];
    self.window = (HSChooserWindow *)self.windowController.window;

    if (!self.windowController.windowLoaded) {
        NSLog(@"ERROR: Unable to load hs.chooser window NIB");
        return NO;
    }

    self.windowController.listTableView.delegate = self;
    self.windowController.listTableView.dataSource = self;
    self.windowController.listTableView.target = self;
    self.windowController.listTableView.doubleAction = @selector(chooseByDoubleClicking:);

    self.windowController.queryField.delegate = self;
    self.windowController.queryField.target = self;
    self.windowController.queryField.action = @selector(choose:);

    return YES;
}

- (void)resizeWindow {
    NSRect screenFrame = [[NSScreen mainScreen] visibleFrame];

    CGFloat rowHeight = [self.windowController.listTableView rowHeight];
    CGFloat intercellHeight =[self.windowController.listTableView intercellSpacing].height;
    CGFloat allRowsHeight = (rowHeight + intercellHeight) * self.numRows;

    CGFloat windowHeight = NSHeight([[self.window contentView] bounds]);
    CGFloat tableHeight = NSHeight([[self.windowController.listTableView superview] frame]);
    CGFloat finalHeight = (windowHeight - tableHeight) + allRowsHeight;

    CGFloat width;
    if (self.width >= 0 && self.width <= 100) {
        CGFloat percentWidth = self.width / 100.0;
        width = NSWidth(screenFrame) * percentWidth;
    } else {
        width = NSWidth(screenFrame) * 0.50;
        width = MIN(width, 800);
        width = MAX(width, 400);
    }

    NSRect winRect = NSMakeRect(0, 0, width, finalHeight);
    [self.window setFrame:winRect display:YES];
    [self.windowController.listTableView setFrameSize:NSMakeSize(winRect.size.width, self.windowController.listTableView.frame.size.height)];
}

- (void)show {
    [self resizeWindow];

    [self.windowController showWindow:self];
    self.window.isVisible = YES;
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];

    [self updateChoices];
}

- (void)hide {
    self.window.isVisible = NO;
}

- (NSInteger) numberOfRowsInTableView:(NSTableView *)tableView {
    NSInteger rowCount = 0;
    NSArray *choices = [self getChoices];

    if (choices) {
        rowCount = choices.count;
    }

    NSLog(@"numberOfRowsInTableView: returning %ld", (long)rowCount);
    return rowCount;
}

- (NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    NSArray *choices = [self getChoices];
    NSDictionary *choice = [choices objectAtIndex:row];

    HSChooserCell *cellView = [tableView makeViewWithIdentifier:@"HSChooserCell" owner:self];

    //cellView.backgroundStyle = NSBackgroundStyleDark;
    NSString *text         = [choice objectForKey:@"text"];
    NSString *subText      = [choice objectForKey:@"subText"];
    NSString *shortcutText = @"";

    if (row >= 0 && row < 9) {
        shortcutText = [NSString stringWithFormat:@"⌘%ld", (long)row + 1];
    }

    cellView.text.stringValue = text ? text : @"UNKNOWN TEXT";
    cellView.subText.stringValue = subText ? subText : @"UNKNOWN SUBTEXT";
    cellView.shortcutText.stringValue = shortcutText ? shortcutText : @"??";
    cellView.image.image = [NSImage imageNamed:NSImageNameFollowLinkFreestandingTemplate];

    return cellView;
}

- (IBAction)choose:(id)sender {
    NSLog(@"in choose:");
}

- (IBAction)chooseByDoubleClicking:(id)sender {
    NSLog(@"in chooseByDoubleClicking:");
}

- (void)updateChoices {
    [self.windowController.listTableView reloadData];
}

- (void)clearChoices {
    self.currentStaticChoices = nil;
    self.currentCallbackChoices = nil;
}

- (void)clearChoicesAndUpdate {
    [self clearChoices];
    [self updateChoices];
}

- (NSArray *)getChoices {
    NSArray *choices = nil;

    if (self.choicesCallbackRef == LUA_NOREF) {
        // No callback is set, we can only return the static choices, even if it's nil
        choices = self.currentStaticChoices;
    } else if (self.choicesCallbackRef != LUA_NOREF) {
        // We have a callback set
        if (!self.currentCallbackChoices) {
            // We have previously cached the callback choices
            LuaSkin *skin = [LuaSkin shared];
            [skin pushLuaRef:*(self.refTable) ref:self.choicesCallbackRef];
            if ([skin protectedCallAndTraceback:0 nresults:1]) {
                self.currentCallbackChoices = [skin toNSObjectAtIndex:-1];
            } else {
                self.currentCallbackChoices = nil;
            }
        }
        choices = self.currentCallbackChoices;
    }

    return choices;
}
@end
