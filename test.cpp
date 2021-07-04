#include <final/final.h>
#include <iostream>
#include <string>
#include <sstream>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <vector>
using namespace std;
using std::cout; using std::endl;
using std::vector; using std::string;

using FKey = finalcut::FKey;
using finalcut::FPoint;
using finalcut::FSize;


 typedef union {
         struct {
                 union {
                         uint8_t l;
                         uint8_t byte;
                 };
                 uint8_t h;
         } __attribute__ (( packed ));
         uint16_t word;
 } __attribute__ (( packed )) reg16_t;
 
 typedef union {
         struct {
                 union {
                         uint8_t l;
                         uint8_t byte;
                 };
                 uint8_t h;
         } __attribute__ (( packed ));
         uint16_t word;
         uint32_t dword;
 } __attribute__ (( packed )) reg32_t;
 
 struct i386_regs {
         union {
                 uint16_t ip;
                 uint32_t eip;
         };
         union {
                 uint16_t di;
                 uint32_t edi;
         };
         union {
                 uint16_t si;
                 uint32_t esi;
         };
         union {
                 uint16_t bp;
                 uint32_t ebp;
         };
         union {
                 uint16_t sp;
                 uint32_t esp;
         };
         union {
                 struct {
                         uint8_t bl;
                         uint8_t bh;
                 } __attribute__ (( packed ));
                 uint16_t bx;
                 uint32_t ebx;
         };
         union {
                 struct {
                         uint8_t dl;
                         uint8_t dh;
                 } __attribute__ (( packed ));
                 uint16_t dx;
                 uint32_t edx;
         };
         union {
                 struct {
                         uint8_t cl;
                         uint8_t ch;
                 } __attribute__ (( packed ));
                 uint16_t cx;
                 uint32_t ecx;
         };
         union {
                 struct {
                         uint8_t al;
                         uint8_t ah;
                 } __attribute__ (( packed ));
                 uint16_t ax;
                 uint32_t eax;
         };
 } __attribute__ (( packed ));
 
 struct i386_seg_regs 
 {
         uint16_t cs;
         uint16_t ss;
         uint16_t ds;
         uint16_t es;
         uint16_t fs;
         uint16_t gs;
 } __attribute__ (( packed ));
 
 struct i386_all_regs 
 {
         struct i386_seg_regs segs;
         struct i386_regs regs;
         uint32_t flags;
 } __attribute__ (( packed ));
 
    
class Memzone
{
    public:
        uint32_t address;
        uint32_t size;
        uint8_t *content;
};

class State {
    public:
        i386_all_regs dump;
        std::vector<Memzone> memzone;
};
    
class Goal {
    public:
        std::string title;
        std::string description;
        std::string help;        
        State init;
        State goal;        
};
    
//----------------------------------------------------------------------
// class TextFixedWindow
//----------------------------------------------------------------------

class TextFixedWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit TextFixedWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    TextFixedWindow (const TextFixedWindow&) = delete;
    // Destructor
    ~TextFixedWindow() override = default;
    // Disable copy assignment operator (=)
    TextFixedWindow& operator = (const TextFixedWindow&) = delete;
    // Method
    void refresh ();
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FLabel fixedtext{this};
};

//----------------------------------------------------------------------
TextFixedWindow::TextFixedWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  fixedtext.setText("pour voir"); 
  fixedtext.ignorePadding();
  fixedtext.setFocus();
}

//----------------------------------------------------------------------
void TextFixedWindow::refresh ()
{
  
}

//----------------------------------------------------------------------
void TextFixedWindow::initLayout()
{
  fixedtext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

//----------------------------------------------------------------------
void TextFixedWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  fixedtext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}


//----------------------------------------------------------------------
// class TextWindow
//----------------------------------------------------------------------

class TextWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit TextWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    TextWindow (const TextWindow&) = delete;
    // Destructor
    ~TextWindow() override = default;
    // Disable copy assignment operator (=)
    TextWindow& operator = (const TextWindow&) = delete;
    // Method
    void append (const finalcut::FString&);
  private:
    // Method
    void onClose (finalcut::FCloseEvent*) override;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FTextView scrolltext{this};
};

//----------------------------------------------------------------------
TextWindow::TextWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  scrolltext.ignorePadding();
  scrolltext.setFocus();
}
//----------------------------------------------------------------------
void TextWindow::onClose (finalcut::FCloseEvent*) 
{
  return;    
}
//----------------------------------------------------------------------
void TextWindow::append (const finalcut::FString& str)
{
  scrolltext.append(str);
}

//----------------------------------------------------------------------
void TextWindow::initLayout()
{
  scrolltext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

//----------------------------------------------------------------------
void TextWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  scrolltext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}

//----------------------------------------------------------------------
// class VMEngine
//----------------------------------------------------------------------

class VMEngine
{
  public:
    VMEngine(TextWindow *log);
    void Configure(State *init);
    void Run();
  private:
    uc_engine *uc;
    uc_err err;
    TextWindow *log;
    std::ostringstream out;
};

VMEngine::VMEngine(TextWindow *log) : log(log)
{
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err != UC_ERR_OK) {
        out << "Impossible d'initialiser la machine virtuelle: " << err;
        log->append(out.str());
    }
    else
        log->append("Initialisation de l'ordinateur IA86");
}

void VMEngine::Configure(State *init)
{
        log->append("Configuration initiale de l'ordinateur IA86");
}

void VMEngine::Run()
{

}

   /*uc_mem_map(uc, ADDRESS, 1 * 1024 * 1024, UC_PROT_ALL);
   if (uc_mem_write(uc, ADDRESS, encode, sizecode)) {
     printf("Failed to write emulation code to memory, quit!\n");
     return -1;
   }
   uc_reg_write(uc, UC_X86_REG_CX, &r_cx);
   uc_reg_write(uc, UC_X86_REG_DX, &r_dx);
   uc_reg_read(uc, UC_X86_REG_IP, &r_ip);
   error=uc_emu_start(uc, ADDRESS, ADDRESS + sizecode, 0, 0);
   if (error) {
     printf("Failed on uc_emu_start() with error returned %u: %s\n",
       err, uc_strerror(error));
   }
   printf("Emulation done. Below is the CPU context\n"); 
   uc_reg_read(uc, UC_X86_REG_CX, &r_cx);
   uc_reg_read(uc, UC_X86_REG_DX, &r_dx);
   uc_reg_read(uc, UC_X86_REG_IP, &r_ip);
   printf(">>> CX = 0x%x\n", r_cx);
   printf(">>> DX = 0x%x\n", r_dx);
   printf(">>> IP = 0x%x\n", r_ip);*/

//----------------------------------------------------------------------
// class Menu
//----------------------------------------------------------------------

class Menu final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit Menu (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    Menu (const Menu&) = delete;
    // Destructor
    ~Menu() override = default;
    // Disable copy assignment operator (=)
    Menu& operator = (const Menu&) = delete;
    // Structures
    // Structures
     // Methods
    void loadGoal(Goal *g, VMEngine *vm);
  private:
    // Methods
    void configureFileMenuItems();
    void defaultCallback (const finalcut::FMenuList*);
    void initLayout() override;
    void adjustSize() override;
    // Event handler
    void onClose (finalcut::FCloseEvent*) override;
    // Callback method
    void cb_message (const finalcut::FMenuItem*);
    // Data members
    finalcut::FString        line{13, finalcut::UniChar::BoxDrawingsHorizontal};
    finalcut::FMenuBar       Menubar{this};
    finalcut::FMenu          File{"&Menu", &Menubar};
    finalcut::FMenuItem      Line2{&File};
    finalcut::FMenuItem      Quit{"&Quit", &File};
    finalcut::FMenuItem      Window{"&Windows", &Menubar};
    finalcut::FLabel         Info{this};
    finalcut::FStatusBar     Statusbar{this};

};

//----------------------------------------------------------------------
Menu::Menu (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  File.setStatusbarMessage ("main menu");
  Window.setDisable();
  configureFileMenuItems();
  defaultCallback (&Menubar);
  Statusbar.setMessage("Status bar message");
  Info << " █████   █████████    ████████    ████████ \n"
       << "░░███   ███░░░░░███  ███░░░░███  ███░░░░███\n"
       << " ░███  ░███    ░███ ░███   ░███ ░███   ░░░ \n"
       << " ░███  ░███████████ ░░████████  ░█████████ \n"
       << " ░███  ░███░░░░░███  ███░░░░███ ░███░░░░███\n"
       << " ░███  ░███    ░███ ░███   ░███ ░███   ░███\n"
       << " █████ █████   █████░░████████  ░░████████ \n"
       << "░░░░░ ░░░░░   ░░░░░  ░░░░░░░░    ░░░░░░░░  \n"
       << "THE EVEN MORE PEDAGOGICAL SYSTEM !!\n"
       << "\n"
       << "Episode 1 : Apprendre l'assembleur X86";
}

//----------------------------------------------------------------------
void Menu::configureFileMenuItems()
{
  Line2.setSeparator();
  Quit.addAccelerator (FKey::Meta_x);
  Quit.setStatusbarMessage ("Quit the program");
  Quit.addCallback
  (
    "clicked",
    finalcut::getFApplication(),
    &finalcut::FApplication::cb_exitApp,
    this
  );
}

//----------------------------------------------------------------------
void Menu::defaultCallback (const finalcut::FMenuList* mb)
{
  for (uInt i{1}; i <= mb->getCount(); i++)
  {
    auto item = mb->getItem(int(i));

    if ( item
      && item->isEnabled()
      && item->acceptFocus()
      && item->isVisible()
      && ! item->isSeparator()
      && item->getText() != "&Quit" )
    {
      item->addCallback
      (
        "clicked",
        this, &Menu::cb_message,
        item
      );
      if ( item->hasMenu() )
        defaultCallback (item->getMenu());
    }
  }
}

//----------------------------------------------------------------------
void Menu::initLayout()
{
  Info.setGeometry(FPoint{2, 1}, FSize{43, 12});
  FDialog::initLayout();
}

//----------------------------------------------------------------------
void Menu::adjustSize()
{
  const auto pw = int(getDesktopWidth());
  const auto ph = int(getDesktopHeight());
  setX (1);
  setY (1);
  finalcut::FDialog::adjustSize();
}

//----------------------------------------------------------------------
void Menu::onClose (finalcut::FCloseEvent* ev)
{
  finalcut::FApplication::closeConfirmationDialog (this, ev);
}

//----------------------------------------------------------------------
void Menu::cb_message (const finalcut::FMenuItem* menuitem)
{
  auto text = menuitem->getText();
  text = text.replace('&', "");
  finalcut::FMessageBox::info ( this
                              , "Info"
                              , "You have chosen \"" + text + "\"" );
}

void Menu::loadGoal(Goal *g, VMEngine *vm)
{
  const auto& view = new TextWindow(this);
  view->setText ("Objectif: "+g->title);
  view->setGeometry ( FPoint { 10, 10 }, FSize{60, 12} );
  view->setResizeable();
  view->append(g->description);
  view->show();
  const auto& test = new TextFixedWindow(this);
  test->setText ("test");
  test->setGeometry ( FPoint { 20, 10 }, FSize{30, 12} );
  test->show();
  vm->Configure(&g->init);
}

 //IP DI SI BP SP BX DX CX AX

Goal goals[]={ 
{
  "L'instruction MOV et les registres","Le but est de bouger du registre AX au registre BX, l' ensemble des données", "Aide....", 
  {
     {
        {},                       
        {}, 
        0x00000000 
     },
     {}
  },
  {
     {
        {},                       
        {.bx=25,.dx=0b101,.cx=0x4650, .ax=0xCCDD}, 
        0x00000000 
     },
     {}
   }
}
};



//----------------------------------------------------------------------
//                               main part
//----------------------------------------------------------------------

int main (int argc, char* argv[])
{
                   
  finalcut::FApplication app {argc, argv};
  Menu main_dlg {&app};
  main_dlg.setText ("IA86 -  Main window");
  main_dlg.setSize ({50, 14});
  main_dlg.setShadow();
  TextWindow log {&main_dlg};
  log.setText ("Journaux");
  log.setGeometry ( FPoint { 30, 10 }, FSize{60, 12} );
  log.setResizeable();
  log.append("lancement des journaux");
  log.show();
  finalcut::FWidget::setMainWidget (&main_dlg);
  main_dlg.show();
  VMEngine vm {&log};
  main_dlg.loadGoal(&goals[0],&vm);
  return app.exec();
}
