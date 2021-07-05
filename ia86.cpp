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
#include "ia86.h"


//----------------------------------------------------------------------
// Fonctions diverses
//----------------------------------------------------------------------

std::string intToHexString(int intValue, int size) {
    string hexStr;
    std::stringstream sstream;
    sstream << std::setfill ('0') << std::setw(size) << std::hex << (int)intValue;
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
      "L'instruction MOV","Le but est de bouger du registre AX au registre BX, l' ensemble des données", "Aide....", "inc ax\ndec cx\nmov ax,0x33\nadd dx,[bx+2]\nmov cx,12", 1,
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
    },
    {
      "Les registres","Il est important de...", "Aide....", "add cl,2\nmov si,0X1234", 2,
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
// Classe ScenarioWindow
//----------------------------------------------------------------------

ScenarioWindow::ScenarioWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  listview.ignorePadding();
  listview.addColumn ("Niv");
  listview.addColumn ("Intitulé");  
  listview.addColumn ("Difficulté");
  listview.addColumn ("Cycles");
  listview.addColumn ("Taille");
  listview.hideSortIndicator(true);
  listview.setFocus();
  std::vector<std::string> items;
  for(size_t i=0; i < (sizeof(goals)/sizeof(goals[0])); i++)
  {
    items.clear();
    items.push_back(to_string(i));
    items.push_back(goals[i].title);
    items.push_back(to_string(goals[i].level));
    const finalcut::FStringList line (items.begin(), items.end());    
    listview.insert (line);
  }
  listview.addCallback
  (
    "row-changed",
    this, &ScenarioWindow::click
  );
}

void ScenarioWindow::click()
{
    const auto& item = listview.getCurrentItem();
    std::string temp=item->getText(1).toString();
    selected=stoi(temp);
    ((Menu*)this->getParent())->loadGoal();
}

int ScenarioWindow::getselected()
{
    return selected;
}

void ScenarioWindow::initLayout()
{
  listview.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

void ScenarioWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  listview.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}

//----------------------------------------------------------------------
// Classe InstructionWindow
//----------------------------------------------------------------------

InstructionWindow::InstructionWindow (finalcut::FWidget* parent)
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

std::vector<std::array<std::string, 5>> InstructionWindow::get()
{
    return content;
}

void InstructionWindow::set(std::vector<std::array<std::string, 5>> src)
{
  content=src;
  listview.clear();
  for (const auto& place : content)
  {
    const finalcut::FStringList line (place.begin(), place.end());
    listview.insert (line);
  }
  
}

void InstructionWindow::initLayout()
{
  listview.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

void InstructionWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  listview.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}
    
//----------------------------------------------------------------------
// Classe TextFixedWindow
//----------------------------------------------------------------------

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
  fixedtext.setGeometry (FPoint{2, 3}, FSize{getWidth()-2, getHeight() - 2});
  FDialog::initLayout();
}

void TextFixedWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  fixedtext.setGeometry (FPoint{2, 3}, FSize(getWidth()-2, getHeight() - 2));
}

//----------------------------------------------------------------------
// Classe TextEditWindow
//----------------------------------------------------------------------

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
  fixedtext.setGeometry (FPoint{2, 3}, FSize{getWidth()-2, getHeight() - 2});
  FDialog::initLayout();
}

void TextEditWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  fixedtext.setGeometry (FPoint{2, 3}, FSize{getWidth()-2, getHeight() - 2});
}

//----------------------------------------------------------------------
// Classe TextWindow
//----------------------------------------------------------------------

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
  scrolltext.scrollBy (0, 10);
}

void TextWindow::clear()
{
  scrolltext.clear();
}


void TextWindow::initLayout()
{
  scrolltext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
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

std::vector<std::array<std::string, 5>> Desassembler::Desassemble(Code *code)
{
    std::stringstream out;
    srcsize=cs_disasm(handle, code->content, code->size, code->address, 0, &insn);
    if (srcsize == 0)
        log->append("Erreur de désassemblage");
    else
    {  
        out << "Désassemblage réussi, taille du source :" << srcsize;
        log->append(out.str());
        src.clear();
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
    code->assembled=false;
}

Code *Assembler::Assemble(std::string source,uint32_t address)
{
    std::stringstream out;
    code->address=address;
    size_t srcsize=source.size();
    unsigned char src_char[srcsize+1];
    strcpy(reinterpret_cast<char*>(src_char), source.c_str());
    err2=ks_asm(ks, reinterpret_cast<const char*>(src_char), code->address, &code->content, &code->size, &srcsize);
    if (err2 != KS_ERR_OK)
    {
        log->append("Erreur d'assemblage");
        code->size=0;
        code->assembled=false;
    }
    else
    {  
        out << "Assemblage réussi, taille du code :" << code->size;
        code->assembled=true;
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
    return code;
}
 
//----------------------------------------------------------------------
// Classe VMEngine
//----------------------------------------------------------------------

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
// Level  1 : IP AL
// Level  2 : IP AX
// Level  3 : IP AX BX CX DX
// Level  4 : IP AX BX CX DX FLAGS
// Level  5 : IP AX BX CX DX FLAGS SI DI
// Level  6 : IP AX BX CX DX FLAGS SI DI SP BP
// Level  7 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS
// Level  8 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS FS GS
// Level  9 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS
// Level 10 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7
// Level 11 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 
// Level 12 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 DB0 DB1 DB2 DB3 DB6 DB7

std::string VMEngine::getRegs(int level)
{
    int regsi836[] = {
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, 
        UC_X86_REG_ESI, UC_X86_REG_EDI, 
        UC_X86_REG_EBP, UC_X86_REG_ESP, 
        UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_FS,UC_X86_REG_GS,
        UC_X86_REG_EIP,UC_X86_REG_EFLAGS
    };
    void *ptrs[sizeof(regsi836)];
    uint32_t vals[sizeof(regsi836)];
    for (size_t i = 0; i < sizeof(regsi836); i++) {
        ptrs[i] = &vals[i];
    }
    err = uc_reg_read_batch(uc, regsi836, ptrs, sizeof(regsi836));
    if (err > 0) {
        log->append("Erreur lors de la récupération des registres depuis la VM");
        return "";
    }
    std::stringstream out;
    if (level > 8)
        out << "EAX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[0] << " | ";
    if (level > 1)
        out << "AX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[0] & 0x0000FFFF) << " | "; 
    if (level > 1)
        out << "AH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[0] & 0xFF00) >> 8) << " | "; 
    out << "AL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[0] & 0xFF) << "\n"; 

    if (level > 8)
        out << "EBX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[1] << " | ";
    if (level > 2)
        out << "BX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[1] & 0x0000FFFF) << " | "; 
    if (level > 2)
        out << "BH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[1] & 0xFF00) >> 8) << " | "; 
    if (level > 2)
        out << "BL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[1] & 0xFF) << "\n"; 
    
    if (level > 8)
        out << "ECX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[2] << " | ";
    if (level > 2)
        out << "CX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[2] & 0x0000FFFF) << " | "; 
    if (level > 2)
        out << "CH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[2] & 0xFF00) >> 8) << " | "; 
    if (level > 2)
        out << "CL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[2] & 0xFF) << "\n"; 
    
    if (level > 8)
        out << "EDX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[3] << " | ";
    if (level > 2)
        out << "DX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[3] & 0x0000FFFF) << " | "; 
    if (level > 2)
        out << "DH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[3] & 0xFF00) >> 8) << " | "; 
    if (level > 2)
        out << "DL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[3] & 0xFF) << "\n"; 
    
    if (level > 8)
        out << "ESI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[4] << " | ";
    if (level > 4)    
        out << "SI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[4] & 0x0000FFFF) << "\n"; 
    if (level > 8)
        out << "EDI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[5] << " | ";
    if (level > 4)
        out << "DI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[5] & 0x0000FFFF) << "\n";
    
    if (level > 8)
        out << "EBP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[6] << " | ";
    if (level > 5)
        out << "BP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[6] & 0x0000FFFF) << "\n"; 
    if (level > 8)
        out << "ESP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[7] << " | ";
    if (level > 5)
        out << "SP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[7] & 0x0000FFFF) << "\n";
    
    if (level > 6)
        out << "CS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[8] & 0x0000FFFF) << " | "; 
    if (level > 6)
        out << "DS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[9] & 0x0000FFFF) << " | "; 
    if (level > 6)
        out << "ES:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[10] & 0x0000FFFF) << "\n"; 
    if (level > 6)
        out << "SS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[11] & 0x0000FFFF) << " | "; 
    if (level > 7)
        out << "FS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[12] & 0x0000FFFF) << " | ";
    if (level > 7) 
        out << "GS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[13] & 0x0000FFFF) << "\n"; 
    
    if (level > 8)
        out << "EIP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[14] << " | ";
    out << "IP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[14] & 0x0000FFFF) << "\n";
    
    if (level > 3)
    if (level < 9)
        out << "FLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << (vals[15]  & 0xFFFF)<< ""; 
    else
        out << "EFLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[15] << ""; 
    return out.str();
}
 
void VMEngine::Configure(State *init, Code *code)
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
        uc_mem_map(uc, init->dump.regs.eip, 1 * 1024 * 1024, UC_PROT_ALL);
        err = uc_mem_write(uc, init->dump.regs.eip, code->content, code->size);
        if (err) 
        {
            code->loaded=false;
            log->append("Erreur de copie mémoire dans la machine virtuelle");
            return;
        }
        else
            code->loaded=true;
}

void VMEngine::Run(Code *code,uint32_t start, uint32_t stop, uint64_t timeout)
{
    err=uc_emu_start(uc, start, stop, timeout, 0);
    if (err) 
    {
        log->append("Erreur lors de l'exécution de la machine virtuelle");
        code->executed=false;
        return;
    }
    else
    {
        code->executed="true";
    }
}

//----------------------------------------------------------------------
// Classe Menu
//----------------------------------------------------------------------

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
  loadGoal();
}

void Menu::initWindows()
{
  log.setText ("Journaux");
  log.setGeometry ( FPoint { 63, 45 }, FSize{60, 11} );
  log.setResizeable();
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
  regs.setGeometry ( FPoint { 01, 01 }, FSize{40, 15} );
  regs.show();
  flags.setText ("Drapeaux");
  flags.setGeometry ( FPoint { 60, 01 }, FSize{15, 15} );
  flags.show();
  stack.setText ("Pile");
  stack.setGeometry ( FPoint { 43, 01 }, FSize{15, 15} );
  stack.show();
  mem.setText ("Mémoire");
  mem.setGeometry ( FPoint { 77, 01 }, FSize{108, 15} );
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
  scenar.setText ("Scénarios");
  scenar.setGeometry ( FPoint { 187, 01 }, FSize{23, 55} );
  scenar.setResizeable();
  scenar.show();
}

// Level  1 : IP AL
// Level  2 : IP AX
// Level  3 : IP AX BX CX DX
// Level  4 : IP AX BX CX DX FLAGS
// Level  5 : IP AX BX CX DX FLAGS SI DI
// Level  6 : IP AX BX CX DX FLAGS SI DI SP BP
// Level  7 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS
// Level  8 : IP AX BX CX DX FLAGS SI DI SP BP CS DS ES SS FS GS
// Level  9 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS
// Level 10 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7
// Level 11 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 
// Level 12 : EIP EAX EBX ECX EDX EFLAGS ESI EDI ESP EBP CS DS ES SS FS GS ST0 ST1 ST2 ST3 ST4 ST5 ST6 ST7 CR0 CR2 CR3 CR4 CR8 DB0 DB1 DB2 DB3 DB6 DB7

void Menu::AdjustWindows()
{
    flags.hide();
    stack.hide();
    mem.hide();
    screen.hide();
    if (goals[scenar.getselected()].level > 3)
        flags.show();
    if (goals[scenar.getselected()].level > 5)
        stack.show();
    if (goals[scenar.getselected()].level > 2)
        mem.show();
    if (goals[scenar.getselected()].level > 6)
        screen.show();              
}

void Menu::initMenus()
{
  Game.setStatusbarMessage ("Menu principal du jeu");
  Options.setStatusbarMessage ("Options du logiciel IA86");
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

void Menu::loadGoal()
{
  view.setText("Objectif: "+goals[scenar.getselected()].title);
  view.clear();
  view.append(goals[scenar.getselected()].description);
  edit.set(goals[scenar.getselected()].code);
  AdjustWindows();
}

void Menu::compile()
{
  code=asmer.Assemble(edit.get(),goals[scenar.getselected()].init.dump.regs.eip);
  debug.set(unasmer.Desassemble(code));
}

void Menu::verify()
{

}

void Menu::exec()
{
  if (!code->assembled)
  {
    finalcut::FMessageBox::error(this, "Vous devez compiler le source d'abord !");
    return;
  }
  if (!code->executed)
    vm.Configure(&goals[scenar.getselected()].init,code);
  vm.Run(code,code->address,code->address+code->size,0);
  regs.set(vm.getRegs(goals[scenar.getselected()].level));
}

void Menu::trace()
{
  if (!code->assembled)
  {
    finalcut::FMessageBox::error(this, "Vous devez compiler le source d'abord !");
    return;
  }
  if (!code->executed)
    vm.Configure(&goals[scenar.getselected()].init,code);  
}

void Menu::step()
{
  if (!code->assembled)
  {
    finalcut::FMessageBox::error(this, "Vous devez compiler le source d'abord !");
    return;
  }
  if (!code->executed)
    vm.Configure(&goals[scenar.getselected()].init,code);  
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
