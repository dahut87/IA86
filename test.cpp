#include <final/final.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
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
        std::string code;        
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
    void refresh();
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
void TextFixedWindow::refresh()
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
// class TextEditWindow
//----------------------------------------------------------------------

class TextEditWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit TextEditWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    TextEditWindow (const TextEditWindow&) = delete;
    // Destructor
    ~TextEditWindow() override = default;
    // Disable copy assignment operator (=)
    TextEditWindow& operator = (const TextEditWindow&) = delete;
    // Method
    std::string get();
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FLabel fixedtext{this};
};

//----------------------------------------------------------------------
TextEditWindow::TextEditWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  fixedtext.setText("pour voir"); 
  fixedtext.ignorePadding();
  fixedtext.setFocus();
}

//----------------------------------------------------------------------
std::string TextEditWindow::get()
{
  return "inc ax\ndec cx\nmov ax,0x33";
}

//----------------------------------------------------------------------
void TextEditWindow::initLayout()
{
  fixedtext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

//----------------------------------------------------------------------
void TextEditWindow::adjustSize()
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
    void append(const finalcut::FString&);
  private:
    // Method
    void onClose(finalcut::FCloseEvent*) override;
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
void TextWindow::onClose(finalcut::FCloseEvent*) 
{
  return;    
}
//----------------------------------------------------------------------
void TextWindow::append(const finalcut::FString& str)
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
// class Asm
//----------------------------------------------------------------------

class Assembler
{
  public:
    Assembler(TextEditWindow *edit,TextWindow *log);
    unsigned char *Assemble(uint32_t address);
  private:
    ks_engine *ks;
    ks_err err;
    int err2;
    TextWindow *log;
    TextEditWindow *edit;
    std::stringstream out;
    size_t srcsize;
    size_t codesize;
    std::string src;
    unsigned char *code = new unsigned char[64*1024];
};

Assembler::Assembler(TextEditWindow *edit,TextWindow *log) : edit(edit),log(log)
{
      err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
    if (err != KS_ERR_OK) {
        out << "Erreur : Initialisation de l'assembleur X86" << err;
        log->append(out.str());
    }
    else
        log->append("Initialisation de l'assembleur X86");
}

unsigned char *Assembler::Assemble(uint32_t address)
{
    src=edit->get();
    srcsize=src.size();
    unsigned char src_char[srcsize+1];
    strcpy(reinterpret_cast<char*>(src_char), src.c_str());
    err2=ks_asm(ks, reinterpret_cast<const char*>(src_char), address, &code, &codesize, &srcsize);
    if (err2 != KS_ERR_OK)
    {
        out << "Erreur de compilation de l'assembleur: " << err;
        log->append(out.str());
    }
    else
    {
        out << "Compilation réussie, taille du code :" << codesize;
        log->append(out.str());
        out.str("");
        out.clear();
        if (codesize < 30)
        {
               out << "  ";
               for (size_t count = 0; count < codesize; count++)
                    out << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (int)((uint8_t)code[count]) ;
               log->append(out.str());   
        }
    }
    return reinterpret_cast<unsigned char*>(&code);
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
    std::stringstream out;
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


 //IP DI SI BP SP BX DX CX AX
 
void VMEngine::Configure(State *init)
{
        out << "Configuration initiale de l'ordinateur IA86:\n  "; 
        err = uc_reg_write(uc, UC_X86_REG_EIP, &init->dump.regs.eip);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EIP");
        else
        if (init->dump.regs.eip != 0x00000000)
            if ((init->dump.regs.eip & 0xFFFF0000) == 0x00000000)
                out << " IP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ip << " ";               
            else
                out << "EIP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eip << " ";     
        err = uc_reg_write(uc, UC_X86_REG_EDI, &init->dump.regs.edi);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EDI");
        else
        if (init->dump.regs.edi != 0x00000000)
            if ((init->dump.regs.edi & 0xFFFF0000) == 0x00000000)
                out << " DI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.di << " ";               
            else
                out << "EDI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESI, &init->dump.regs.esi);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: ESE");
        else
        if (init->dump.regs.esi != 0x00000000)
            if ((init->dump.regs.esi & 0xFFFF0000) == 0x00000000)
                out << " SI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.si << " ";               
            else
                out << "ESI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBP, &init->dump.regs.ebp);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EBP");
        else
        if (init->dump.regs.ebp != 0x00000000) 
            if ((init->dump.regs.ebp & 0xFFFF0000) == 0x00000000)
                out << " BP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bp << " ";               
            else
                out << "EBP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESP, &init->dump.regs.esp);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: ESP");
        else
        if (init->dump.regs.esp != 0x00000000)
            if ((init->dump.regs.esp & 0xFFFF0000) == 0x00000000)
                out << " SP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.sp << " ";               
            else
                out << "ESP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBX, &init->dump.regs.ebx);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EBX");
        else
        if (init->dump.regs.ebx != 0x00000000)
            if ((init->dump.regs.ebx & 0xFFFF0000) == 0x00000000)
                out << " BX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bx << " ";               
            else
                out << "EBX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EDX, &init->dump.regs.edx);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EDX");
        else
        if (init->dump.regs.edx != 0x00000000)
            if ((init->dump.regs.edx & 0xFFFF0000) == 0x00000000)
                out << " DX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.dx << " ";               
            else
                out << "EDX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ECX, &init->dump.regs.ecx);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: ECX");
        else
        if (init->dump.regs.ecx != 0x00000000)
            if ((init->dump.regs.ecx & 0xFFFF0000) == 0x00000000)
                out << " CX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.cx << " ";               
            else
                out << "ECX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ecx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EAX, &init->dump.regs.eax);
        if (err != UC_ERR_OK)
           log->append("Impossible d'initialiser le registre: EAX");
        else
        if (init->dump.regs.eax != 0x00000000)
            if ((init->dump.regs.eax & 0xFFFF0000) == 0x00000000)
                out << " AX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ax << " ";               
            else
                out << "EAX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eax << " ";               
        log->append(out.str());
}

void VMEngine::Run()
{

}

   /*uc_mem_map(uc, ADDRESS, 1 * 1024 * 1024, UC_PROT_ALL);
   if (uc_mem_write(uc, ADDRESS, encode, sizecode)) {
   error=uc_emu_start(uc, ADDRESS, ADDRESS + sizecode, 0, 0);*/

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
  "L'instruction MOV et les registres","Le but est de bouger du registre AX au registre BX, l' ensemble des données", "Aide....", "mov ax,immédiat",
  {
     {
        {},                       
        {.bx=0x0002,.ax=0x1920}, 
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
  main_dlg.setText ("IA86");
  main_dlg.setSize ({50, 14});
  main_dlg.setShadow();
  TextWindow log {&main_dlg};
  log.setText ("Journaux");
  log.setGeometry ( FPoint { 30, 10 }, FSize{60, 12} );
  log.setResizeable();
  log.append("Lancement des journaux");
  log.show();
  TextEditWindow edit {&main_dlg};
  edit.setText ("Code source");
  edit.setGeometry ( FPoint { 30, 10 }, FSize{60, 12} );
  edit.setResizeable();
  edit.show();
  finalcut::FWidget::setMainWidget (&main_dlg);
  main_dlg.show();
  VMEngine vm {&log};
  Assembler asmer {&edit,&log};
  asmer.Assemble(0x0000);
  main_dlg.loadGoal(&goals[0],&vm);
  return app.exec();
}
