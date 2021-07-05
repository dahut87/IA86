#include <final/final.h>
#include <unistd.h>
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

//----------------------------------------------------------------------
// Types & classes mineures
//----------------------------------------------------------------------
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
// Fonctions diverses
//----------------------------------------------------------------------

std::string intToHexString(int intValue, int size) {
    string hexStr;
    std::stringstream sstream;
    sstream << std::setfill ('0') << std::setw(size)
    << std::hex << (int)intValue;
    hexStr= sstream.str();
    sstream.clear();
    return hexStr;
}

//----------------------------------------------------------------------
// Objectifs de jeux
//----------------------------------------------------------------------

    // Ordre des registres ... IP DI SI BP SP BX DX CX AX
Goal goals[]=
{ 
    {
      "L'instruction MOV et les registres","Le but est de bouger du registre AX au registre BX, l' ensemble des données", "Aide....", "inc ax\ndec cx\nmov ax,0x33\nadd ax,[bx+2]",
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
// Classe ListWindow
//----------------------------------------------------------------------

class ListWindow final : public finalcut::FDialog
{
  public:
    // Constructor
    explicit ListWindow (finalcut::FWidget* = nullptr);
    // Disable copy constructor
    ListWindow (const ListWindow&) = delete;
    // Destructor
    ~ListWindow() override = default;
    // Disable copy assignment operator (=)
    ListWindow& operator = (const ListWindow&) = delete;
    // Method
    std::vector<std::array<std::string, 5>> get();
    void set(std::vector<std::array<std::string, 5>> src);
  private:
    // Method
    std::vector<std::array<std::string, 5>> content;
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FListView listview{this};
};

ListWindow::ListWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  listview.ignorePadding();
  listview.addColumn ("P");
  listview.addColumn ("Adresse");
  listview.addColumn ("Opcodes     ");
  listview.addColumn ("Mnémo.");
  listview.addColumn ("Opérandes");
  listview.hideSortIndicator(true);
  listview.setFocus();
}

std::vector<std::array<std::string, 5>> ListWindow::get()
{
    return content;
}

void ListWindow::set(std::vector<std::array<std::string, 5>> src)
{
  content=src;
  listview.clear();
  for (const auto& place : content)
  {
    const finalcut::FStringList line (place.begin(), place.end());
    listview.insert (line);
  }
  
}

void ListWindow::initLayout()
{
  listview.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

void ListWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  listview.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}
    
//----------------------------------------------------------------------
// Classe TextFixedWindow
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
    std::string get();
    void set(std::string str);
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FLabel fixedtext{this};
};

TextFixedWindow::TextFixedWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  fixedtext.ignorePadding();
  fixedtext.setFocus();
}

std::string TextFixedWindow::get()
{
  std::stringstream out;
  out << fixedtext.getText();
  return out.str();
}

void TextFixedWindow::set(std::string str)
{
  fixedtext.setText(str);
}

void TextFixedWindow::initLayout()
{
  fixedtext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

void TextFixedWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  fixedtext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}

//----------------------------------------------------------------------
// Classe TextEditWindow
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
    void set(std::string str);
  private:
    // Method
    void initLayout() override;
    void adjustSize() override;
    // Data members
    finalcut::FLabel fixedtext{this};
};

TextEditWindow::TextEditWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  fixedtext.ignorePadding();
  fixedtext.setFocus();
}

std::string TextEditWindow::get()
{
  std::stringstream out;
  out << fixedtext.getText();
  return out.str();
}

void TextEditWindow::set(std::string str)
{
  fixedtext.setText(str);
}

void TextEditWindow::initLayout()
{
  fixedtext.setGeometry (FPoint{2, 3}, FSize(12, 12));
  FDialog::initLayout();
}

void TextEditWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
}

//----------------------------------------------------------------------
// Classe TextWindow
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


TextWindow::TextWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  scrolltext.ignorePadding();
  scrolltext.setFocus();
}

void TextWindow::onClose(finalcut::FCloseEvent*) 
{
  return;    
}

void TextWindow::append(const finalcut::FString& str)
{
  scrolltext.append(str);
  scrolltext.scrollBy (0, 1);
}

void TextWindow::initLayout()
{
  scrolltext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

void TextWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  scrolltext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}

//----------------------------------------------------------------------
// Classe Desassembler
//----------------------------------------------------------------------
class Desassembler
{
  public:
    Desassembler(TextWindow *log);
    std::vector<std::array<std::string, 5>> Desassemble(unsigned char* code,size_t codesize,uint32_t address);
  private:
    csh handle;
    cs_insn *insn;
    int err;
    TextWindow *log;
    TextEditWindow *edit;
    size_t srcsize;
    size_t codesize;
    std::vector<std::array<std::string, 5>> src;
    unsigned char *src_char = new unsigned char[64*1024];
};

Desassembler::Desassembler(TextWindow *log) : log(log)
{
    std::stringstream out;
    err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
    if (err != CS_ERR_OK) {
        out << "Erreur : Initialisation du désassembleur X86" << err;
        log->append(out.str());
    }
    else
        log->append("Initialisation du désassembleur X86");
}

std::vector<std::array<std::string, 5>> Desassembler::Desassemble(unsigned char* code,size_t codesize,uint32_t address)
{
    std::stringstream out;
    srcsize=cs_disasm(handle, code, codesize, address, 0, &insn);
    if (srcsize == 0)
        log->append("Erreur de désassemblage");
    else
    {  
        out << "Désassemblage réussi, taille du source :" << srcsize;
        log->append(out.str());
		for (size_t j = 0; j < srcsize; j++)
		{
		    std::string *bytes = new std::string("");
		    for (size_t k = 0; k < insn[j].size; k++)
                *bytes=*bytes+intToHexString((int)insn[j].bytes[k], 1);
            std::string adresse = intToHexString((int)insn[j].address, 8);  
		    std::string *menmonic = new std::string((char *)insn[j].mnemonic);
		    std::string *op_str = new std::string((char *)insn[j].op_str);
		    std::array<std::string, 5> *array = new  std::array<std::string, 5>{"", adresse, *bytes, *menmonic, *op_str};
		    src.push_back(*array);
        }
		cs_free(insn, srcsize);
    }
    return src;
}

//----------------------------------------------------------------------
// Classe Assembler
//----------------------------------------------------------------------
class Assembler
{
  public:
    Assembler(TextWindow *log);
    unsigned char *Assemble(std::string source,uint32_t address);
    size_t getCodesize();
  private:
    ks_engine *ks;
    ks_err err;
    int err2;
    TextWindow *log;
    TextEditWindow *edit;
    size_t srcsize;
    size_t codesize;
    std::string src;
    unsigned char *code = new unsigned char[64*1024];
};

Assembler::Assembler(TextWindow *log) : log(log)
{
    std::stringstream out;
    err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
    if (err != KS_ERR_OK) {
        out << "Erreur : Initialisation de l'assembleur X86" << err;
        log->append(out.str());
    }
    else
        log->append("Initialisation de l'assembleur X86");
}

size_t Assembler::getCodesize()
{
    return codesize;
}

unsigned char *Assembler::Assemble(std::string source,uint32_t address)
{
    std::stringstream out;
    src=source;
    srcsize=src.size();
    unsigned char src_char[srcsize+1];
    strcpy(reinterpret_cast<char*>(src_char), src.c_str());
    err2=ks_asm(ks, reinterpret_cast<const char*>(src_char), address, &code, &codesize, &srcsize);
    if (err2 != KS_ERR_OK)
    {
        log->append("Erreur d'assemblage");
        codesize=0;
    }
    else
    {  
        out << "Assemblage réussi, taille du code :" << codesize;
        log->append(out.str());
        /*out.str("");
        out.clear();
        if (codesize < 30)
        {
               out << "  ";
               for (size_t count = 0; count < codesize; count++)
                    out << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (int)((uint8_t)code[count]) ;
               log->append(out.str());   
        }*/
    }
    return reinterpret_cast<unsigned char*>(code);
}
 
//----------------------------------------------------------------------
// Classe VMEngine
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
};

VMEngine::VMEngine(TextWindow *log) : log(log)
{
    std::stringstream out; 
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
        std::stringstream out;
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
// Classe Menu
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
     // Methods
    void setGoal(int num);
    void loadGoal();
  private:
    int  scenario=0;
    unsigned char *code;
    bool compiled=false;
    void configureFileMenuItems();
    void initMenusCallBack ();
    void initMenus();
    void initMisc();
    void initNow();
    void initCore();
    void compile();
    void exec();
    void trace();
    void step();
    void verify();
    void initWindows();
    void splash();
    void initLayout() override;
    void adjustSize() override;
    // Event handler
    void onClose (finalcut::FCloseEvent*) override;
    // Callback method
    void cb_message (const finalcut::FMenuItem*);
    // Data members
    finalcut::FString        line{13, finalcut::UniChar::BoxDrawingsHorizontal};
    finalcut::FMenuBar       Menubar{this};
    finalcut::FMenu          Game{"&Partie", &Menubar};
    finalcut::FMenuItem      New{"&Nouvelle partie", &Game};
    finalcut::FMenuItem      Line2{&Game};
    finalcut::FMenuItem      Quit{"&Quitter", &Game};
    finalcut::FMenu          Scenarios{"&Scénarios", &Menubar};
    finalcut::FMenu          Tools{"&Outils", &Menubar};
    finalcut::FMenuItem      Assemble{"&Compilation", &Tools};
    finalcut::FMenuItem      Rearange{"&Ordonne les fenêtres", &Tools};
    finalcut::FMenu          Debug{"&Déboguage", &Menubar};
    finalcut::FMenuItem      Run{"&Exécuter", &Debug};
    finalcut::FMenuItem      End{"&Terminer", &Debug};
    finalcut::FMenuItem      TraceInto{"Pas à pas &détaillé", &Debug}; 
    finalcut::FMenuItem      StepOver{"&Pas à pas", &Debug};
    finalcut::FMenuItem      Breakpoint{"&Point d'arrêt", &Debug};
    finalcut::FDialogListMenu Window{"&Fenêtres", &Menubar};
    finalcut::FMenu          Help{"&Aide", &Menubar}; 
    finalcut::FMenuItem      About{"&A propos", &Help}; 
    finalcut::FLabel         Info{this};
    finalcut::FStatusBar     Statusbar{this};
    TextWindow               log{this};
    TextWindow               view{this};
    ListWindow               debug{this};
    TextFixedWindow          regs{this};
    TextFixedWindow          flags{this};
    TextFixedWindow          stack{this};
    TextFixedWindow          mem{this};
    TextFixedWindow          tuto{this};
    TextFixedWindow          screen{this};
    TextEditWindow           edit{this};
    VMEngine                 vm{&log};
    Assembler                asmer{&log};
    Desassembler             unasmer{&log};
};

Menu::Menu (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  initNow();
}

void Menu::initNow()
{
  initWindows();
  initMisc();
  initMenus();
  initMenusCallBack();
  initCore();
}

void Menu::initCore()
{
  setGoal(0);
}
//EAX:00000000 | AX:0000 | AH:00 | AL:00
void Menu::initWindows()
{
  log.setText ("Journaux");
  log.setGeometry ( FPoint { 63, 45 }, FSize{60, 11} );
  log.setResizeable();
  log.append("Lancement des journaux");
  log.show();
  edit.setText ("Code source");
  edit.setGeometry ( FPoint { 01, 17 }, FSize{39, 27} );
  edit.setResizeable();
  edit.show();
  view.setText ("Objectif");
  view.setGeometry ( FPoint { 01, 45 }, FSize{60, 11} );
  view.setResizeable();
  view.show();
  regs.setText ("Registres");
  regs.setGeometry ( FPoint { 01, 01 }, FSize{39, 15} );
  regs.show();
  flags.setText ("Drapeaux");
  flags.setGeometry ( FPoint { 59, 01 }, FSize{15, 15} );
  flags.show();
  stack.setText ("Pile");
  stack.setGeometry ( FPoint { 42, 01 }, FSize{15, 15} );
  stack.show();
  mem.setText ("Mémoire");
  mem.setGeometry ( FPoint { 76, 01 }, FSize{109, 15} );
  mem.show();
  tuto.setText ("Guide");
  tuto.setGeometry ( FPoint { 125, 45 }, FSize{60, 11} );
  tuto.setResizeable();
  tuto.show();
  screen.setText ("Ecran");
  screen.setGeometry ( FPoint { 105, 18 }, FSize{80, 25} );
  screen.show();
  debug.setText ("Instructions");
  debug.setGeometry ( FPoint { 42, 17 }, FSize{60, 27} );
  debug.setResizeable();
  debug.show();
}

void Menu::initMenus()
{
  Game.setStatusbarMessage ("Menu principal du jeu");
  Scenarios.setStatusbarMessage ("Scénario disponibles");
  Tools.setStatusbarMessage ("Outils divers");
  Debug.setStatusbarMessage ("Fonctionnalitées de déboguages");
  Window.setStatusbarMessage ("Fenêtres en cours d'exécution");
  Help.setStatusbarMessage ("Aide et informations IA86");
  Line2.setSeparator();
  New.addAccelerator (FKey::Meta_n);
  New.setStatusbarMessage ("Debuter une nouvelle partie"); 
  Quit.addAccelerator (FKey::Meta_x);
  Quit.setStatusbarMessage ("Quitter IA86"); 
  Run.addAccelerator (FKey::Meta_f9);
  Run.setStatusbarMessage ("Exécuter le programme - seul un breakpoint arrête"); 
  TraceInto.addAccelerator (FKey::F7);
  TraceInto.setStatusbarMessage ("Pas à pas détaillé - entre dans les CALL"); 
  StepOver.addAccelerator (FKey::F8);
  StepOver.setStatusbarMessage ("Pas à pas - ne rentre pas dans les CALL"); 
  Assemble.addAccelerator (FKey::F2);
  Assemble.setStatusbarMessage ("Assemble le source vers du code machine"); 
  Rearange.addAccelerator (FKey::F1);
  Rearange.setStatusbarMessage ("Reorganise les fenêtres dans leur état initial");   
  Breakpoint.addAccelerator (FKey::F5);
  Breakpoint.setStatusbarMessage ("Enlève ou met un point d'arrêt"); 
  End.addAccelerator (FKey::Meta_f2);
  End.setStatusbarMessage ("Termine le programme et remet à zéro la machine IA86");
  About.setStatusbarMessage ("A propos de IA86"); 
}

void Menu::initMenusCallBack()
{
  Quit.addCallback
  (
    "clicked",
    finalcut::getFApplication(),
    &finalcut::FApplication::cb_exitApp,
    this
  );
  Assemble.addCallback
  (
    "clicked",
    this,
    &Menu::compile
  );
  Run.addCallback
  (
    "clicked",
    this,
    &Menu::exec
  );
  Rearange.addCallback
  (
    "clicked",
    this,
    &Menu::initWindows
  );
  TraceInto.addCallback
  (
    "clicked",
    this,
    &Menu::trace
  );
  StepOver.addCallback
  (
    "clicked",
    this,
    &Menu::step
  );
}

void Menu::initMisc()
{
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
    Statusbar.setMessage("THE EVEN MORE PEDAGOGICAL SYSTEM !!");
}

void Menu::initLayout()
{
  Info.setGeometry(FPoint{2, 1}, FSize{43, 12});
  FDialog::initLayout();
}

void Menu::adjustSize()
{
  const auto pw = int(getDesktopWidth());
  const auto ph = int(getDesktopHeight());
  setX (1 + (pw - int(getWidth())) / 2, false);
  setY (1 + (ph - int(getHeight())) / 4, false);
  finalcut::FDialog::adjustSize();
}

void Menu::onClose (finalcut::FCloseEvent* ev)
{
  finalcut::FApplication::closeConfirmationDialog (this, ev);
}

void Menu::setGoal(int num)
{
    scenario=num;
    loadGoal();
}

void Menu::loadGoal()
{
  view.setText("Objectif: "+goals[scenario].title);
  view.append(goals[scenario].description);
  edit.set(goals[scenario].code);
}

void Menu::compile()
{
  code=asmer.Assemble(edit.get(),goals[scenario].init.dump.regs.eip);
  debug.set(unasmer.Desassemble(code,asmer.getCodesize(),goals[scenario].init.dump.regs.eip));
  compiled=(asmer.getCodesize()>0);
}

void Menu::verify()
{
  if (!compiled)
  {
    finalcut::FMessageBox::error(this, "Vous devez compiler le source d'abord !");
    return;
  }
}

void Menu::exec()
{
  verify(); 
  vm.Configure(&goals[scenario].init);
}

void Menu::trace()
{
  verify();
}

void Menu::step()
{
  verify();

}

//----------------------------------------------------------------------
// Fonction Main
//----------------------------------------------------------------------
int main (int argc, char* argv[])
{
                   
  finalcut::FApplication app {argc, argv};
  Menu main_dlg {&app};
  main_dlg.setText ("IA86");
  main_dlg.setSize ({50, 14});
  main_dlg.setShadow();
  main_dlg.show();
  finalcut::FWidget::setMainWidget (&main_dlg);
  //usleep(5 * 1000000);
  main_dlg.hide();
  return app.exec();
}
