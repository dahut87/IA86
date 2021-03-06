#include <final/final.h>
#include <unistd.h>
#include <regex>
#include <iostream>
#include <sstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <vector>
#include <zlib.h>
#include "ia86.h"
#include <exception>
#include "struct_mapping/struct_mapping.h"



//----------------------------------------------------------------------
// Fonctions diverses
//----------------------------------------------------------------------

std::string intToHexString(int intValue, int size) {
    string hexStr;
    std::stringstream sstream;
    sstream << std::uppercase << std::setfill ('0') << std::setw(size) << std::hex << (int)intValue;
    hexStr= sstream.str();
    sstream.clear();
    return hexStr;
}

void mapping()
{
    struct_mapping::reg(&Scenario::title, "scenario_titre");
    struct_mapping::reg(&Scenario::levels, "scenario_objectifs");
    struct_mapping::reg(&Level::title, "niveau_titre");
    struct_mapping::reg(&Level::description, "niveau_description");
    struct_mapping::reg(&Level::tutorial, "niveau_tutoriel");
    struct_mapping::reg(&Level::code, "niveau_code");
    struct_mapping::reg(&Level::rights, "niveau_droits");
    struct_mapping::reg(&Level::init, "niveau_initial");
    struct_mapping::reg(&Level::goal, "niveau_objectif");
    struct_mapping::reg(&State::dump, "registres");
    struct_mapping::reg(&State::code, "code");
    struct_mapping::reg(&i386_all_regs::segs, "segments");
    struct_mapping::reg(&i386_all_regs::regs, "généraux");
    struct_mapping::reg(&i386_all_regs::flags, "drapeaux");
    struct_mapping::reg(&i386_segs::cs, "cs");
    struct_mapping::reg(&i386_segs::ss, "ss");
    struct_mapping::reg(&i386_segs::ds, "ds");
    struct_mapping::reg(&i386_segs::es, "es");
    struct_mapping::reg(&i386_segs::fs, "fs");
    struct_mapping::reg(&i386_segs::gs, "gs");
    struct_mapping::reg(&i386_regs::eax, "eax");
    struct_mapping::reg(&i386_regs::ebx, "ebx");
    struct_mapping::reg(&i386_regs::ecx, "ecx");
    struct_mapping::reg(&i386_regs::edx, "edx");
    struct_mapping::reg(&i386_regs::esi, "esi");
    struct_mapping::reg(&i386_regs::edi, "edi");
    struct_mapping::reg(&i386_regs::esp, "esp");
    struct_mapping::reg(&i386_regs::ebp, "ebp");
    struct_mapping::reg(&i386_regs::eip, "eip"); 
}

Scenario scenario;
Level level;
Unasm unasm;
int marker;
bool debugnow;
uc_hook uh_mem;
uc_hook uh_code;
uc_hook uh_call;
uc_hook uh_int;
bool step=false;
bool call=false;
bool ok=false;
bool executed=false;
bool initialized=false;
uint32_t hadcall=0x0;
std::vector<std::array<uint32_t,2>> breakpoints;

//----------------------------------------------------------------------
// Classe ScenarioWindow
//----------------------------------------------------------------------

ScenarioWindow::ScenarioWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  listview.ignorePadding();
  listview.addColumn ("*");
  listview.addColumn ("Intitulé");  
  listview.hideSortIndicator(true);
  listview.setFocus();
  listview.addCallback
  (
    "row-changed",
    this, &ScenarioWindow::click
  );
}

void ScenarioWindow::click()
{
    ((Menu*)this->getParent())->loadLevel(listview.getindex());
}

void ScenarioWindow::Load(std::vector<Level> levels)
{
    vector<std::string> items;
    listview.clear();
    for(size_t i=0; i < levels.size(); i++)
    {
        //((Menu*)this->getParent())->tolog(".");
        items.clear();
        items.push_back(to_string(i));
        items.push_back(levels[i].title);
        const finalcut::FStringList line (items.begin(), items.end());    
        listview.insert(line);
    }
} 

void ScenarioWindow::initLayout()
{
  listview.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
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
  listview.addColumn ("Adresse");
  listview.addColumn ("Opcodes     ");
  listview.addColumn ("Mnémo.");
  listview.addColumn ("Opérandes");
  listview.hideSortIndicator(true);
  listview.setFocus();
}

std::vector<std::array<std::string, 4>> InstructionWindow::get()
{
    return content;
}

void InstructionWindow::clear()
{
  listview.clear();
  listview.redraw();
}

std::string InstructionWindow::getaddress()
{
    return listview.getCurrentItem()->getText(1).c_str();
}

void InstructionWindow::setmark(int index)
{
  listview.setmark(index);
}

int InstructionWindow::getindex()
{
  return listview.getindex();
}

void InstructionWindow::setmultimark(std::vector<int> mark)
{
    listview.setmultimark(mark);
}

int InstructionWindow::getsize()
{
  return listview.getCount();
}

void InstructionWindow::set(std::vector<std::array<std::string, 4>> src)
{
  content=src;
  listview.clear();
  for (const auto& place : content)
  {
    const finalcut::FStringList line (place.begin(), place.end());
    listview.insert (line);
  }
  listview.redraw();
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
// Classe CodeWindow
//----------------------------------------------------------------------

CodeWindow::CodeWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{

  listview.ignorePadding();
  listview.addColumn ("Num");
  listview.addColumn ("Titre");
  listview.addColumn ("Adresse");
  listview.addColumn ("Taille");
  listview.addColumn ("Source");
  listview.addColumn ("Assemblé");
  listview.addColumn ("Chargé");
  listview.hideSortIndicator(true);
  listview.setFocus();
}

std::vector<std::array<std::string, 7>> CodeWindow::get()
{
    return content;
}

void CodeWindow::clear()
{
  listview.clear();
  listview.redraw();
}

int CodeWindow::getindex()
{
  return listview.getindex();
}

int CodeWindow::getsize()
{
  return listview.getCount();
}

void CodeWindow::set(std::vector<std::array<std::string, 7>> src)
{
  content=src;
  listview.clear();
  for (const auto& place : content)
  {
    const finalcut::FStringList line (place.begin(), place.end());
    listview.insert (line);
  }
  listview.redraw();
}

void CodeWindow::initLayout()
{
  listview.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  setMinimumSize (FSize{51, 6});
  FDialog::initLayout();
}

void CodeWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  listview.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
}    

//----------------------------------------------------------------------
// Classe TextEditWindow
//----------------------------------------------------------------------

TextEditWindow::TextEditWindow (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  scrolltext.ignorePadding();
  scrolltext.setFocus();
}

void TextEditWindow::onClose(finalcut::FCloseEvent*) 
{
  return;    
}

void TextEditWindow::append(const finalcut::FString& str)
{
  scrolltext.append(str);
  scrolltext.scrollBy (0, 10);
}

std::string TextEditWindow::get()
{
  return scrolltext.getText().toString() ;
}

void TextEditWindow::set(const finalcut::FString& str)
{
  scrolltext.clear(); 
  scrolltext.append(str);
  scrolltext.redraw();
}

void TextEditWindow::clear()
{
  scrolltext.clear();
}


void TextEditWindow::initLayout()
{
  scrolltext.setGeometry (FPoint{1, 2}, FSize{getWidth(), getHeight() - 1});
  FDialog::initLayout();
}

void TextEditWindow::adjustSize()
{
  finalcut::FDialog::adjustSize();
  scrolltext.setGeometry (FPoint{1, 2}, FSize(getWidth(), getHeight() - 1));
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

std::string TextWindow::get()
{
  return scrolltext.getText().toString() ;
}

void TextWindow::set(const finalcut::FString& str)
{
  scrolltext.clear(); 
  scrolltext.append(str);
  scrolltext.redraw();
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

Desassembler::Desassembler(Menu *widget) : widget(widget)
{
    try
    {
        err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
        if (err != CS_ERR_OK) 
            throw Error("Désassembleur - initialisation....................[ERREUR]");
        if (debugnow)
            widget->tolog("Désassembleur - initialisation....................[  OK  ]");
    }
    catch(exception const& e)
    {
       widget->tolog(e.what());
    }
}

void Desassembler::setSyntax(int syntax)
{
    cs_option(handle, CS_OPT_SYNTAX, syntax);
}

void Desassembler::Desassemble(uint8_t *content, uint32_t address,uint32_t size, Unasm *unasm)
{
    try
    {
        srcsize=cs_disasm(handle, content, size, address, 0, &insn);
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        if (srcsize == 0)
            throw Error("Désassembleur - désassemblage.....................[ERREUR]");
        else
        {  
            if (debugnow) widget->tolog("Désassemblage - désassemblage.....................[ "+to_string(srcsize)+"l ]");
            unasm->src.clear();
            unasm->pos.clear();
		    for (size_t j = 0; j < srcsize; j++)
		    {
		        std::string *bytes = new std::string("");
		        for (size_t k = 0; k < insn[j].size; k++)
                    *bytes=*bytes+intToHexString((int)insn[j].bytes[k], 2);
                std::string adresse = intToHexString((int)insn[j].address, 8);  
		        std::string *menmonic = new std::string((char *)insn[j].mnemonic);
		        std::string *op_str = new std::string((char *)insn[j].op_str);
		        std::array<std::string, 4> *array = new  std::array<std::string, 4>{adresse, *bytes, *menmonic, *op_str};
		        unasm->src.push_back(*array);
		        unasm->pos.push_back(insn[j].address);
            }
		    cs_free(insn, srcsize);
        }
    }
    catch(exception const& e)
    {
       unasm->src.clear();
       unasm->pos.clear();
       widget->tolog(e.what());
    }

}

//----------------------------------------------------------------------
// Classe Assembler
//----------------------------------------------------------------------

Assembler::Assembler(Menu *widget) : widget(widget)
{
    try
    {
        err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
        if (err != KS_ERR_OK) 
            throw Error("Assembleur - initialisation.......................[ERREUR]");
        if (debugnow)
            widget->tolog("Assembleur - initialisation.......................[  OK  ]");
    }
    catch(exception const& e)
    {
       widget->tolog(e.what());
    }
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
}

void Assembler::setSyntax(int syntax)
{
    ks_option(ks, KS_OPT_SYNTAX, syntax);
}

std::vector<Code> Assembler::MultiAssemble(std::string source,uint32_t address)
{
    try
    {
        std::vector<Code> mcode;
        std::istringstream stream(source);
        std::string line;
        std::regex regex_org("^ *.org 0x([0-F]+)$");
        std::regex regex_name("^ *.title ([a-zA-Z0-9_]+)$");
        Code *code=new Code;
        bool begin=true;
        int org=address;
        code->address=org;
        while (std::getline(stream, line)) 
        {
            if (line.find(".org") != std::string::npos)
            {
                std::smatch match;
                if(std::regex_search(line, match, regex_org))
                {
                    org=std::stoul(match.str(1), nullptr, 16);
                }
                if (!begin)
                {
                    mcode.push_back(*code);
                    code=new Code;
                    code->address=org;
                }
            }    
            else if (line.find(".title") != std::string::npos)
            {
                std::smatch match;
                if(std::regex_search(line, match, regex_name))
                {
                    code->name=match.str(1);
                }
            }
            else
            {
                code->src.append(line+"\n");
            }
            begin=false;
        }
        if (code->src.size()>0)
            mcode.push_back(*code);
        for(size_t i=0;i<mcode.size();i++)
            this->Assemble(&mcode[i]);
        widget->tolog("Assembleur - assemblage...........................[  OK  ]");
        return mcode;
     }
    catch(exception const& e)
    {
       std::vector<Code> mcode;
       widget->tolog(e.what());
       return mcode;
    }

}

void Assembler::Assemble(Code *code)
{
    size_t srcsize=code->src.size();
    unsigned char src_char[srcsize+1];
    strcpy(reinterpret_cast<char*>(src_char), code->src.c_str());
    err2=ks_asm(ks, reinterpret_cast<const char*>(src_char), code->address, &code->content, &code->size, &srcsize);
    if (err2 != KS_ERR_OK)
    {
        code->size=0;
        code->assembled=false;
        code->loaded=false;
        throw Error("Assembleur - assemblage...........................[ERREUR]\n  Nombre:"+to_string(srcsize)+"\n  Erreur:"+std::string(ks_strerror(ks_errno(ks))));
    }
    else
        code->assembled=true;
}
 
//----------------------------------------------------------------------
// Classe VMEngine
//----------------------------------------------------------------------

VMEngine::VMEngine(Menu *widget) : widget(widget)
{
    code=new uint8_t[500];
    Init();
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
std::string VMEngine::getFlags()
{
        int eflags=0;
        err = uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
        if (err != UC_ERR_OK)
            throw Error("VM IA86 - voir EFLAGS.............................[ERREUR]");
        std::stringstream out;
        out << "  CF:" << std::dec << ((eflags & 0x0001));
        if (rights > 8) 
            out << "  RF:" << std::dec << ((eflags & 0x00010000)>>16) << "\n";
        else
            out << "\n"; 
        out << "  PF:" << std::dec << ((eflags & 0x0004)>>2); 
        if (rights > 8)
            out << "  VM:" << std::dec << ((eflags & 0x00020000)>>17) << "\n";
        else
            out << "\n";
        out << "  AF:" << std::dec << ((eflags & 0x0010)>>4);    
        if (rights > 8)
            out << "  AC:" << std::dec << ((eflags & 0x00040000)>>18) << "\n";
        else
            out << "\n";
        out << "  ZF:" << std::dec << ((eflags & 0x0040)>>6);
        if (rights > 8)
            out << " VIF:" << std::dec << ((eflags & 0x00080000)>>19) << "\n";
        else
            out << "\n";
        out << "  SF:" << std::dec << ((eflags & 0x0080)>>7);
        if (rights > 8)
            out << " VIP:" << std::dec << ((eflags & 0x00100000)>>20) << "\n";      
        else
            out << "\n";
        out << "  TF:" << std::dec << ((eflags & 0x0100)>>8);
        if (rights > 8)
            out << "  ID:" << std::dec << ((eflags & 0x00200000)>>21) << "\n";
        else
            out << "\n";
        out << "  IF:" << std::dec << ((eflags & 0x0200)>>9) << "\n";        
        out << "  DF:" << std::dec << ((eflags & 0x0400)>>10) << "\n";        
        out << "  OF:" << std::dec << ((eflags & 0x0800)>>11) << "\n";        
        out << "IOPL:" << std::dec << ((eflags & 0x3000)>>12) << "\n";        
        out << "  NT:" << std::dec << ((eflags & 0x4000)>>13) << "\n";    
        return out.str();    
}

std::string VMEngine::getStack()
{
    uint16_t *code=new uint16_t[12];
    std::string result="";
    uint16_t SS=getSS();
    uint32_t ESP=getESP();
    uint32_t EBP=getEBP();
    int realaddress=SS*16+ESP-12;
    if (realaddress<0)
        realaddress=0;
    //((Menu *)widget)->tolog(intToHexString(realaddress,8));
    err = uc_mem_read(uc, realaddress, code, 2*12);
    if (err)
        throw Error("VM IA86 - voir pile...............................[ERREUR]");
    for(int i=11;i>=0;i--)
    {
        result+=intToHexString(code[i],4);
        if (realaddress+i*2==SS*16+ESP)
            result+="<ESP";
        if (realaddress+i*2==SS*16+EBP)
            result+="<EBP"; 
        result+="\n";           
    }
    return result;
}

std::string VMEngine::getRegs()
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
        throw Error("VM IA86 - voir REGISTRES..........................[ERREUR]");
        return "";
    }
    std::stringstream out;
    if (rights > 8)
        out << "EAX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[0] << " | ";
    if (rights > 1)
        out << "AX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[0] & 0x0000FFFF) << " | "; 
    if (rights > 1)
        out << "AH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[0] & 0xFF00) >> 8) << " | "; 
    out << "AL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[0] & 0xFF) << "\n"; 

    if (rights > 8)
        out << "EBX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[1] << " | ";
    if (rights > 2)
        out << "BX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[1] & 0x0000FFFF) << " | "; 
    if (rights > 2)
        out << "BH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[1] & 0xFF00) >> 8) << " | "; 
    if (rights > 2)
        out << "BL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[1] & 0xFF) << "\n"; 
    
    if (rights > 8)
        out << "ECX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[2] << " | ";
    if (rights > 2)
        out << "CX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[2] & 0x0000FFFF) << " | "; 
    if (rights > 2)
        out << "CH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[2] & 0xFF00) >> 8) << " | "; 
    if (rights > 2)
        out << "CL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[2] & 0xFF) << "\n"; 
    
    if (rights > 8)
        out << "EDX:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[3] << " | ";
    if (rights > 2)
        out << "DX:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[3] & 0x0000FFFF) << " | "; 
    if (rights > 2)
        out << "DH:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ((vals[3] & 0xFF00) >> 8) << " | "; 
    if (rights > 2)
        out << "DL:" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (vals[3] & 0xFF) << "\n"; 
    
    if (rights > 8)
        out << "ESI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[4] << " | ";
    if (rights > 4)    
        out << "SI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[4] & 0x0000FFFF) << "\n"; 
    if (rights > 8)
        out << "EDI:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[5] << " | ";
    if (rights > 4)
        out << "DI:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[5] & 0x0000FFFF) << "\n";
    
    if (rights > 8)
        out << "EBP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[6] << " | ";
    if (rights > 5)
        out << "BP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[6] & 0x0000FFFF) << "\n"; 
    if (rights > 8)
        out << "ESP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[7] << " | ";
    if (rights > 5)
        out << "SP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[7] & 0x0000FFFF) << "\n";
    
    if (rights > 6)
        out << "CS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[8] & 0x0000FFFF) << " | "; 
    if (rights > 6)
        out << "DS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[9] & 0x0000FFFF) << " | "; 
    if (rights > 6)
        out << "ES:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[10] & 0x0000FFFF) << "\n"; 
    if (rights > 6)
        out << "SS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[11] & 0x0000FFFF) << " | "; 
    if (rights > 7)
        out << "FS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[12] & 0x0000FFFF) << " | ";
    if (rights > 7) 
        out << "GS:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[13] & 0x0000FFFF) << "\n"; 
    
    if (rights > 8)
        out << "EIP:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[14] << " | ";
    out << "IP:" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << (vals[14] & 0x0000FFFF) << "\n";
    
    if (rights > 3)
    if (rights < 9)
        out << "FLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << (vals[15]  & 0xFFFF)<< ""; 
    else
        out << "EFLAGS:" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << vals[15] << ""; 
    return out.str();
}

void VMEngine::Init()
{
    try
    {
        hadcall=0;
        err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
        if (err != UC_ERR_OK)
            throw Error("VM IA86 - initilisation...........................[ERREUR]");
        if (debugnow)
            widget->tolog("VM IA86 - initilisation...........................[  OK  ]");
    }
    catch(exception const& e)
    {
        widget->tolog(e.what());
    }
}

bool VMEngine::isExecuted()
{
    return executed;
}

bool VMEngine::isInitialized()
{
    return initialized;
}

void VMEngine::Close()
{
   uc_close(uc);
}

void VMEngine::Halt()
{
    if (executed && debugnow)
        widget->tolog("VM IA86 - arret...................................[ INFO ]");
   executed=false;
}

void VMEngine::Unconfigure()
{
   this->clearbreakpoints();
   this->Halt();
    if (initialized)
        widget->tolog("VM IA86 - déconfiguration.........................[ INFO ]");
   initialized=false;
}

std::string VMEngine::getRam(int segment, int address,int lines, int linesize)
{   
    int reallinesize=(int)((linesize-16)/4);
    int size=reallinesize*(lines-3);
    uint32_t realaddress=segment*16+address;
    if (realaddress>1024*1024)
        return "Zone en dehors de la mémorie";
    uint8_t *code=new uint8_t[512];
    std::string result="";
    std::string line;
    err = uc_mem_read(uc, realaddress, code, 500);
    if (err)
        throw Error("VM IA86 - voir mémoire............................[ERREUR]");
    for(size_t i=0;i<size;i++)
    {
        if ((i%reallinesize)==0)
        {
            if (i!=0) 
                result+=" | "+line+"\n";
            result+=intToHexString(address+i,8)+" | ";
            line="";
        }
        result+=intToHexString(code[i],2)+" ";
        if (std::isprint(code[i]))
            line+=(char)code[i];
        else
            line+='.';
    }
    result+=" | "+line+"\n";
    return result;
}

std::vector<std::array<std::string, 7>> VMEngine::getCode()
{
    int line=0;
    std::vector<std::array<std::string, 7>> result;
    for(Code code: mcode)
    {   
        std::string *linestr = new std::string(to_string(line++));
        std::string *name = new std::string(code.name);
        std::string *address = new std::string(intToHexString(code.address,8));
        std::string *size = new std::string(to_string(code.size));
        std::string *srcsize = new std::string(to_string(code.src.size()));
        std::string *assembled = new std::string;
        if (code.assembled)
            *assembled="X";
        std::string *loaded = new std::string;
        if (code.loaded)
            *loaded="X";
        std::array<std::string, 7> *array = new  std::array<std::string, 7>{*linestr,*name,*address,*size,*srcsize,*assembled,*loaded};
		result.push_back(*array);
    }
    return result;
}


std::vector<std::array<std::string, 4>> VMEngine::getInstr(int segment, int address,int size)
{   
    uint32_t realaddress=segment*16+address;
    if (realaddress<bufferaddress || realaddress+(size*7)>bufferaddress+500)
    {
        bufferaddress=realaddress-30;
        if (bufferaddress<0) 
            bufferaddress=0x00000000;
        address_old=address-30;
        if (address_old<0) 
            address_old=0x00000000;
    }
    err = uc_mem_read(uc, bufferaddress, code, 500);
    if (err) 
        throw Error("VM IA86 - cache instructions......................[ERREUR]");
    crc = crc32(0,  code, 500);
    if (crc != crc_old)
    {
        unasmer.Desassemble(code, address_old, 500, &unasm);
        if (unasm.src.size()==0)
            throw Error("VM IA86 - cache instructions......................[ERREUR]");
        crc_old=crc;
    }    
    int line=0;
    for(int pos: unasm.pos)
    {
       if (pos==address)
            break;
       line++;
    }  
    int first=line-((int)size/2);
    if (first<0) first=0;
    int last=first+size;
    marker=0;
    std::string reference=intToHexString(address, 8);
    std::vector<std::array<std::string, 4>> result = {unasm.src.begin()+first,unasm.src.begin()+last};
    for(std::array<std::string, 4> item: result)
    {
        if (item[0]==reference)
            break;
        marker++;
    }
    return result;
}


int VMEngine::getLine()
{
    return marker;
}

void VMEngine::clearbreakpoints()
{
    breakpoints.clear();
}

void VMEngine::addbreakpoint(uint16_t segment,uint32_t address)
{
    for(std::array<uint32_t,2> item: breakpoints)
        if (item[1]==address && item[0]==segment) return;
    breakpoints.push_back({segment,address});
}

void VMEngine::removebreakpoint(uint16_t segment,uint32_t address)
{
    int i=0;
    for(std::array<uint32_t,2> item: breakpoints)
        if (item[1]==address && item[0]==segment) 
        {
            breakpoints.erase(breakpoints.begin()+i);
            return;
        }    
}

std::vector<int> VMEngine::getBreapoints()
{
    std::vector<int> list;
    std::vector<std::array<std::string, 4>> items=((Menu*)widget)->getsrc();
    for(std::array<uint32_t,2> bp: breakpoints)
    {
        int line=0;
        for(std::array<std::string, 4> item: items)
        {
            if (item[0]==intToHexString(bp[1],8) && getCS()==bp[0])
            {
                //((Menu*)widget)->tolog(to_string(line));
                list.push_back(line);
                break;
            }
            line++;
        }
    }
    return list;
}
 
    
//----------------------------------------------------------------------
// Hook
//----------------------------------------------------------------------
    

static void hook_int(uc_engine *uc, uint32_t intno, void *user_data)
{
    ((Menu *)user_data)->tolog("INT "+to_string(intno));
}

static void hook_code (uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
   if (!ok) 
    {
        ok=true;
        return;
    }
    uint8_t code[2];
    uc_err err = uc_mem_read(uc, address, &code, 2);
    if (err) 
        throw Error("VM IA86 - hook instructions.......................[ERREUR]");
    //((Menu *)user_data)->tolog(intToHexString(code[0],2));
    //((Menu *)user_data)->tolog(intToHexString(code[1],2));
    bool breakp=false;
    for(std::array<uint32_t,2> bp: breakpoints)
        if (address==bp[0]*16+bp[1])
        {
            breakp=true;
            break;
        }
    if (!breakp && (!step || (hadcall>0 && !call))) return;
    if (code[0]==0xF4)      
        executed=false;
    else if (step && (code[0]==0xE8 || code[0]==0xFF || code[0]==0x9A || (code[0]==0x66 && (code[1]==0xE8 || code[1]==0xFF || code[1]==0x9A))))
        hadcall=address+size;
    else
        hadcall=0;    
    uc_emu_stop(uc);
}

static void hook_call(uc_engine *uc, uint32_t intno, void *user_data)
{
    ((Menu *)user_data)->tolog("SYSCALL");
}


static void hook_memory_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    switch (type)
    {
    case UC_MEM_WRITE:
        if ((address>=0xB8000) && (address<=0xB8000+80*25*2))
        {
               uint16_t offset=address-0xB8000;
               uint16_t y=(int)(offset/(80*2));
               uint16_t x=offset%(80*2);
               char achar;
               if (std::isprint(value))
                    achar=(char)value;
               else
                    achar='.';
               if ((size==1) && (x%2==0))
                    ((Menu *)user_data)->SetScreen(x/2,y,achar);
        }
    }
}
void VMEngine::Configure(State *init, std::string code)
{
    try
    {
        int status;
        mcode.clear();
        mcode=asmer.MultiAssemble(code,init->dump.regs.eip);
        if (mcode.size()==0)
            return;
        Close();
        Init();
        bufferaddress=-1;
        initialized=false;
        executed=false;
        hadcall=0x0;
        //widget->tolog("Mappage de la mémoire virtuelle");
        uc_mem_map(uc, 0, 1 * 1024 * 1024, UC_PROT_ALL);
        uc_hook_add(uc, &uh_call, UC_HOOK_INSN, (void*)hook_call, (void*)widget, 1, 0, UC_X86_INS_SYSCALL);
        uc_hook_add(uc, &uh_mem, UC_HOOK_MEM_WRITE, (void*)hook_memory_write, (void*)widget, 1, 0);
        uc_hook_add(uc, &uh_code, UC_HOOK_CODE, (void*)hook_code, (void*)widget, 1, 0);
        uc_hook_add(uc, &uh_int, UC_HOOK_INTR, (void*)hook_int, (void*)widget, 1, 0);
        for(size_t i=0;i<mcode.size();i++)
        {
           if (mcode[i].assembled) 
                SetMem(&mcode[i]);
           else     
                throw Error("VM IA86 - code non assemblé...................[ERREUR]");
           if (debugnow) widget->tolog("Section N°"+std::to_string(i)+" : "+intToHexString(mcode[i].address,8)+" -> "+to_string(mcode[i].size)+" octets");
        }
        status=verify();
        if (status==0)
        {
            initialized=true;
            SetRegs(init);   
        }
        else
            initialized=false;
    }
    catch(exception const& e)
    {
        widget->tolog(e.what());
        initialized=false;
    }
}

int VMEngine::verify()
{
   for(Code code: mcode)
   {
      if (!code.assembled)
        return 1;
      else if (!code.loaded)
         return 2;       
   }
   return 0;
}

void VMEngine::setSyntax(int asmsyntax,int unasmsyntax)
{
    asmer.setSyntax(asmsyntax);
    unasmer.setSyntax(unasmsyntax);
}

void VMEngine::setRights(int rights)
{
    this->rights=rights;
}

uint32_t VMEngine::getCurrent()
{
    return getEIP()+getCS()*16;
}

uint32_t VMEngine::getESI()
{
        int esi;
        err = uc_reg_read(uc, UC_X86_REG_ESI, &esi);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir ESI................................[ERREUR]");
        return esi;
}

uint32_t VMEngine::getEDI()
{
        uint32_t edi;
        err = uc_reg_read(uc, UC_X86_REG_EDI, &edi);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir EDI................................[ERREUR]");
        return edi;
}

uint32_t VMEngine::getESP()
{
        uint32_t esp;
        err = uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir ESP................................[ERREUR]");
        return esp;
}

uint32_t VMEngine::getEBP()
{
        uint32_t ebp;
        err = uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir EBP................................[ERREUR]");
        return ebp;
}

uint32_t VMEngine::getEIP()
{
        uint32_t eip;
        err = uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir EIP................................[ERREUR]");
        return eip;
}

uint16_t VMEngine::getCS()
{
        uint16_t cs;
        err = uc_reg_read(uc, UC_X86_REG_CS, &cs);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir CS.................................[ERREUR]");
        return cs;
}

uint16_t VMEngine::getDS()
{
        uint16_t ds;
        err = uc_reg_read(uc, UC_X86_REG_DS, &ds);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir DS.................................[ERREUR]");
        return ds;
}

uint16_t VMEngine::getES()
{
        uint16_t es;
        err = uc_reg_read(uc, UC_X86_REG_ES, &es);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir ES.................................[ERREUR]");
        return es;
}

uint16_t VMEngine::getSS()
{
        uint16_t ss;
        err = uc_reg_read(uc, UC_X86_REG_SS, &ss);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - voir SS.................................[ERREUR]");
        return ss;
}

void VMEngine::SetMem(Code *code)
{

        err = uc_mem_write(uc, code->address, code->content, code->size);
        if (err) 
        {
            code->loaded=false;
            throw Error("VM IA86 - copie mémoire...........................[ERREUR]");
            return;
        }
        code->loaded=true;
}
 
void VMEngine::SetRegs(State *init)
{
        std::stringstream out;
        out << "VM IA86 - configuration initiale..................[  OK  ]"; 
        err = uc_reg_write(uc, UC_X86_REG_EIP, &init->dump.regs.eip);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EIP..............[ERREUR]");
        else
        if (init->dump.regs.eip != 0x00000000)
            if ((init->dump.regs.eip & 0xFFFF0000) == 0x00000000)
                out << " IP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ip << " ";               
            else
                out << "EIP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eip << " ";     
        err = uc_reg_write(uc, UC_X86_REG_EDI, &init->dump.regs.edi);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EDI..............[ERREUR]");
        else
        if (init->dump.regs.edi != 0x00000000)
            if ((init->dump.regs.edi & 0xFFFF0000) == 0x00000000)
                out << " DI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.di << " ";               
            else
                out << "EDI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESI, &init->dump.regs.esi);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale ESI..............[ERREUR]");
        else
        if (init->dump.regs.esi != 0x00000000)
            if ((init->dump.regs.esi & 0xFFFF0000) == 0x00000000)
                out << " SI=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.si << " ";               
            else
                out << "ESI=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esi << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBP, &init->dump.regs.ebp);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EBP..............[ERREUR]");
        else
        if (init->dump.regs.ebp != 0x00000000) 
            if ((init->dump.regs.ebp & 0xFFFF0000) == 0x00000000)
                out << " BP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bp << " ";               
            else
                out << "EBP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ESP, &init->dump.regs.esp);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale ESP..............[ERREUR]");
        else
        if (init->dump.regs.esp != 0x00000000)
            if ((init->dump.regs.esp & 0xFFFF0000) == 0x00000000)
                out << " SP=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.sp << " ";               
            else
                out << "ESP=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.esp << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EBX, &init->dump.regs.ebx);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EBX..............[ERREUR]");
        else
        if (init->dump.regs.ebx != 0x00000000)
            if ((init->dump.regs.ebx & 0xFFFF0000) == 0x00000000)
                out << " BX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.bx << " ";               
            else
                out << "EBX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ebx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EDX, &init->dump.regs.edx);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EDX..............[ERREUR]");
        else
        if (init->dump.regs.edx != 0x00000000)
            if ((init->dump.regs.edx & 0xFFFF0000) == 0x00000000)
                out << " DX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.dx << " ";               
            else
                out << "EDX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.edx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_ECX, &init->dump.regs.ecx);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale ECX..............[ERREUR]");
        else
        if (init->dump.regs.ecx != 0x00000000)
            if ((init->dump.regs.ecx & 0xFFFF0000) == 0x00000000)
                out << " CX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.cx << " ";               
            else
                out << "ECX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.ecx << " ";               
        err = uc_reg_write(uc, UC_X86_REG_EAX, &init->dump.regs.eax);
        if (err != UC_ERR_OK)
           throw Error("VM IA86 - configuration initiale EAX..............[ERREUR]");
        else
        if (init->dump.regs.eax != 0x00000000)
            if ((init->dump.regs.eax & 0xFFFF0000) == 0x00000000)
                out << " AX=" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << init->dump.regs.ax << " ";               
            else
                out << "EAX=" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << init->dump.regs.eax << " ";    
        if (debugnow)           
            widget->tolog(out.str());
}

void VMEngine::Run(bool astep, bool acall, uint64_t timeout)
{
    try
    {
        if (verify()==0 && initialized)
        {
            ok=false;
            step=astep;
            call=acall;
            if (hadcall==0)
                err=uc_emu_start(uc, this->getCurrent(), 0xFFFFFFFF, timeout, 0);
            else
            {
                err=uc_emu_start(uc, this->getCurrent(), hadcall, timeout, 0);
                hadcall=0;
            }
            if (err) 
                throw Error("VM IA86 - execution...............................[ERREUR]");
            else
            {
                if (!executed && debugnow)
                    widget->tolog("VM IA86 - execution...............................[ INFO ]");
                executed="true";
            }
        }
   }
   catch(exception const& e)
   {
        this->Halt();
        widget->tolog(e.what());
   }
}

//----------------------------------------------------------------------
// Classe Menu
//----------------------------------------------------------------------

Menu::Menu (finalcut::FWidget* parent)
  : finalcut::FDialog{parent}
{
  initWindows();
  initMisc();
  initMenus();
  initMenusCallBack();
  loadScenario("./scenarios.json");
  addTimer(50);
  if (debugnow)
    tolog("DEBOGUAGE ACTIVE !");
}

void Menu::initWindows()
{
  this->setText ("Journaux");
  this->show(); 
  info.setText ("Informations");
  info.setResizeable();
  info.show(); 
  edit.setText ("Code source");
  edit.setResizeable();
  edit.show();
  view.setText ("Objectif");
  view.setResizeable();
  view.show();
  regs.setText ("Registres");
  regs.show();
  flags.setText ("Drapeaux");
  stack.setText ("Pile");
  mem.setText ("Mémoire");
  mem.setResizeable();
  tuto.setText ("Guide");
  tuto.setResizeable();
  tuto.show();
  screen.setText ("Ecran");
  debug.setText ("Instructions");
  debug.setResizeable();
  debug.show();
  scenar.setText ("Scénarios");
  scenar.show();
}

// Level  1 : IP AL
// Level  2 : I:P AX
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
  this->setGeometry ( FPoint { 63, 45 }, FSize{60, 11} );
  codes.setGeometry ( FPoint { 63, 45 }, FSize{60, 11} );
  edit.setGeometry ( FPoint { 01, 17 }, FSize{39, 27} );
  view.setGeometry ( FPoint { 01, 45 }, FSize{60, 11} );
  regs.setGeometry ( FPoint { 01, 01 }, FSize{40, 15} );
  flags.setGeometry ( FPoint { 60, 01 }, FSize{15, 15} );
  stack.setGeometry ( FPoint { 43, 01 }, FSize{15, 15} );
  mem.setGeometry ( FPoint { 77, 01 }, FSize{108, 15} );
  tuto.setGeometry ( FPoint { 125, 45 }, FSize{60, 11} );
  screen.setGeometry ( FPoint { 103, 16 }, FSize{82, 28} );
  debug.setGeometry ( FPoint { 42, 17 }, FSize{60, 27} );
  scenar.setGeometry ( FPoint { 187, 01 }, FSize{25, 55} );
  info.setGeometry (FPoint { 55, 25 }, FSize{50, 14});
  this->show();
  info.hide();
  flags.hide();
  stack.hide();
  mem.hide();
  screen.hide();
  if (scenario.loaded)
  {
      codes.show();
      info.show();
      edit.show();
      view.show();
      regs.show();
      tuto.show();
      debug.show();
      scenar.show();
      if (level.rights > 3)
            flags.show();
      if (level.rights > 5)
            stack.show();
      if (level.rights > 2)
            mem.show();
      if (level.rights > 6)
            screen.show();
      New.setEnable();
      Open.setEnable();
      Save.setEnable();
      Close.setEnable();
      Assemble.setEnable();
      Run.setEnable();
      End.setEnable();
      TraceInto.setEnable();
      StepOver.setEnable();
      AddBp.setEnable();
      ClearBp.setEnable();
      ClearAllBp.setEnable();
  }
  else
  {
      edit.hide();
      view.hide();
      regs.hide();
      tuto.hide();
      debug.hide();
      scenar.hide();
      New.setDisable();
      Open.setDisable();
      Save.setDisable();
      Close.setDisable();
      Assemble.setDisable();
      Run.setDisable();
      End.setDisable();
      TraceInto.setDisable();
      StepOver.setDisable();
      AddBp.setDisable();
      ClearBp.setDisable();
      ClearAllBp.setDisable();
  }
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
  Line3.setSeparator();
  New.addAccelerator (FKey::Meta_n);
  New.setStatusbarMessage ("Debuter une nouvelle partie"); 
  Quit.addAccelerator (FKey::Meta_x);
  Quit.setStatusbarMessage ("Quitter IA86"); 
  Run.addAccelerator (FKey::F9);
  Run.setStatusbarMessage ("Exécuter le programme - seul un breakpoint arrête"); 
  TraceInto.addAccelerator (FKey::F7);
  TraceInto.setStatusbarMessage ("Pas à pas détaillé - entre dans les CALL"); 
  StepOver.addAccelerator (FKey::F8);
  StepOver.setStatusbarMessage ("Pas à pas - ne rentre pas dans les CALL"); 
  Assemble.addAccelerator (FKey::F2);
  Assemble.setStatusbarMessage ("Assemble le source vers du code machine"); 
  Rearange.addAccelerator (FKey::Meta_r);
  Rearange.setStatusbarMessage ("Reorganise les fenêtres dans leur état initial");   
  Breakpoint.addAccelerator (FKey::F5);
  Breakpoint.setStatusbarMessage ("Enlève ou met un point d'arrêt"); 
  End.addAccelerator (FKey::F6);
  End.setStatusbarMessage ("Termine le programme et remet à zéro la machine IA86");
  About.setStatusbarMessage ("A propos de IA86");
  AddBp.addAccelerator (FKey::F4);
}

void Menu::ClearScreen()
{
    std::string empty="";
    for(int i=0;i<80*25;i++)
    {
       if ((i%80==0) && i!=0)
        empty+="\n";
       empty+="X";
    }
    screen.set(empty);
}

void Menu::SetScreen(uint16_t x, uint16_t y, char value)
{
    std::string temp=screen.get();
    if (x<25 && y<80)
        temp[x+y*81]=value;
    screen.set(temp);
}

void Menu::onTimer (finalcut::FTimerEvent* ev)
{
  refresh();
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
  About.addCallback
  (
    "clicked",
    this,
    &Menu::about
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
    &Menu::AdjustWindows
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
  End.addCallback
  (
    "clicked",
    this,
    &Menu::end
  );
  AddBp.addCallback
  (
    "clicked",
    this,
    &Menu::addbp
  );
  AsmAtt.addCallback
  (
    "clicked",
    this,
    &Menu::changesyntax
  );
  UnasmAtt.addCallback
  (
    "clicked",
    this,
    &Menu::changesyntax
  );
  Ds_000.addCallback
  (
    "clicked",
    this,
    &Menu::showInstr
  );
  Ds_esi.addCallback
  (
    "clicked",
    this,
    &Menu::showInstr
  );
  Es_edi.addCallback
  (
    "clicked",
    this,
    &Menu::showInstr
  );
  Cs_eip.addCallback
  (
    "clicked",
    this,
    &Menu::showInstr
  );
  Ss_esp.addCallback
  (
    "clicked",
    this,
    &Menu::showInstr
  );
  Ss_FFF.addCallback
  (
    "clicked",
    this,
    &Menu::showInstr
  );
  OpenScenar.addCallback
  (
    "clicked",
    this,
    &Menu::openscenar
  );
  CloseScenar.addCallback
  (
    "clicked",
    this,
    &Menu::closescenar
  );
}

void Menu::initMisc()
{
  info.set("\
 █████   █████████    ████████    ████████ \n\
░░███   ███░░░░░███  ███░░░░███  ███░░░░███\n\
 ░███  ░███    ░███ ░███   ░███ ░███   ░░░ \n\
 ░███  ░███████████ ░░████████  ░█████████ \n\
 ░███  ░███░░░░░███  ███░░░░███ ░███░░░░███\n\
 ░███  ░███    ░███ ░███   ░███ ░███   ░███\n\
 █████ █████   █████░░████████  ░░████████ \n\
░░░░░ ░░░░░   ░░░░░  ░░░░░░░░    ░░░░░░░░  \n\
THE EVEN MORE PEDAGOGICAL SYSTEM !!\n\
\n\
Episode 1 : Apprendre l'assembleur X86");
    Statusbar.setMessage("THE EVEN MORE PEDAGOGICAL SYSTEM !!");
}

void Menu::initLayout()
{
  this->setGeometry ( FPoint { 63, 45 }, FSize{60, 11}, false);
  this->setTopPadding(1);
  this->setLeftPadding(0);
  this->setRightPadding(0);
  this->setBottomPadding(0);
  Ds_000.setChecked();
  Log.setGeometry (FPoint{0, 0}, FSize{getWidth(), getHeight()},false);
  FDialog::initLayout();
}

void Menu::onClose (finalcut::FCloseEvent* ev)
{
  finalcut::FApplication::closeConfirmationDialog (this, ev);
}

void Menu::closeLevel()
{
  vm.Unconfigure();
  AdjustWindows();
}

/*void Menu::loadBios(std::string file)
{

    std::ifstream input(file, std::ios::binary );
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(input), {});
   
}*/

void Menu::loadScenario(std::string file)
{

   scenario.loaded=false;
   std::ifstream inFile;
   inFile.open(file);
   std::stringstream strStream;
   strStream << inFile.rdbuf();
   std::string json=strStream.str();
   std::istringstream json_data(json);
   scenario.levels.clear();
   struct_mapping::map_json_to_struct(scenario, json_data);
   if (scenario.levels.size()>0) 
   {
      scenar.Load(scenario.levels);
      scenario.loaded=true;
      if (debugnow)
        tolog("Application - charge scénarios....................[  OK  ]");
      tolog("-={ "+ scenario.title+" }=-");
      loadLevel(0);
   }
   else
   {
       tolog("Application - charge scénarios....................[ERREUR]");
       closeLevel();
   }
   inFile.close();
}

void Menu::loadLevel(int alevel)
{
  if (scenario.levels[alevel].title!=level.title)
  {
      vm.Unconfigure();
      level=scenario.levels[alevel];
      if (debugnow)
        tolog("Application - charge niveau.......................[ INFO ]");
      view.setText("Objectif: "+level.title);
      view.clear();
      view.append(level.description);
      tuto.clear();
      tuto.append(level.tutorial);
      edit.set(level.code);
      debug.clear();
      vm.setRights(level.rights);
      AdjustWindows();
      showInstr();
  }
}

void Menu::end()
{
  vm.Halt();
}

void Menu::compile()
{
    vm.Configure(&level.init,edit.get());
    codes.set(vm.getCode());
    ClearScreen();
    showInstr();
}

void Menu::tolog(std::string str)
{
    this->Log.append(str);
    this->Log.scrollBy (0, 10);
}

void Menu::openscenar()
{
  finalcut::FString file{};
  file = finalcut::FFileDialog::fileOpenChooser (this);
  if ( file.isEmpty() )
    return;
  else
    loadScenario(file.c_str());
}

void Menu::closescenar()
{
    scenario.loaded=false;

    level.title="";
    closeLevel();
}

void Menu::about()
{
  this->hide();
  edit.hide();
  view.hide();
  regs.hide();
  flags.hide();
  stack.hide();
  mem.hide();
  tuto.hide();
  screen.hide();
  debug.hide();
  scenar.hide();
  info.show();
  finalcut::FFocusEvent event (finalcut::Event::ChildFocusIn);
  ((finalcut::FApplication*)this->getParent())->queueEvent(&info, &event);
  usleep(5000000);
  AdjustWindows();
}

std::vector<std::array<std::string, 4>> Menu::getsrc()
{
    return debug.get();
}

void Menu::showInstr()
{
    try
    {
        if (vm.isInitialized())
        {
            try
            {
                debug.set(vm.getInstr(vm.getCS(),vm.getEIP(),debug.getHeight()-3));
                debug.setmark(vm.getLine());
                debug.setmultimark(vm.getBreapoints());
                regs.set(vm.getRegs());
                flags.set(vm.getFlags());
                stack.set(vm.getStack());
                if (Ds_000.isChecked())
                    mem.set(vm.getRam(vm.getDS(), 0x000000000, mem.getHeight(),mem.getWidth()));
                else if (Ds_esi.isChecked())
                    mem.set(vm.getRam(vm.getDS(), vm.getESI(), mem.getHeight(),mem.getWidth()));
                else if (Es_edi.isChecked())
                    mem.set(vm.getRam(vm.getES(), vm.getEDI(), mem.getHeight(),mem.getWidth()));
                else if (Cs_eip.isChecked())
                    mem.set(vm.getRam(vm.getCS(), vm.getEIP(), mem.getHeight(),mem.getWidth()));
                else if (Ss_esp.isChecked())
                    mem.set(vm.getRam(vm.getSS(), vm.getESP(), mem.getHeight(),mem.getWidth()));
                else if (Ss_FFF.isChecked())
                    mem.set(vm.getRam(vm.getSS(), 0x0000FF20, mem.getHeight(),mem.getWidth()));
             }
             catch(exception const& e)
            {
                tolog(e.what());
                vm.Halt();
                vm.Unconfigure();
            }
        }
        else
        {
            regs.set("En attente d'initialisation...");
            flags.set("Attente...");
            stack.set("Attente...");
            mem.set("En attente d'initialisation...");
            screen.set("En attente d'initialisation...");        
        }
    }
    catch(exception const& e)
    {
        tolog(e.what());
        vm.Halt();
    }
}

void Menu::refresh()
{
  if (!vm.isExecuted())
  {
    finalcut::FApplication::setDarkTheme();
  }
  else
  {
    finalcut::FApplication::setDefaultTheme();
  }
  auto root_widget = getRootWidget();
  root_widget->resetColors();
  root_widget->redraw();
}

void Menu::exec()
{
  if (!vm.isInitialized())
    compile();
   vm.Run(false,false,0);
   showInstr();
}

void Menu::trace()
{
  if (!vm.isInitialized())
    compile();
  vm.Run(true,false,0);
  showInstr();
}

void Menu::step()
{
  if (!vm.isInitialized())
    compile(); 
  vm.Run(true,true,0);
  showInstr();
}

void Menu::changesyntax()
{
    int asmsyntax,unasmsyntax;
    if (AsmAtt.isChecked())
        asmsyntax=KS_OPT_SYNTAX_ATT;
    else
        asmsyntax=KS_OPT_SYNTAX_INTEL;
    if (UnasmAtt.isChecked())    
        unasmsyntax=CS_OPT_SYNTAX_ATT;
    else 
        unasmsyntax=CS_OPT_SYNTAX_INTEL;
    vm.setSyntax(asmsyntax,unasmsyntax);
    showInstr();
}

void Menu::addbp()
{
    if (vm.isInitialized())
    {
        std::string address=debug.getaddress();
        if (debugnow)
            tolog("VM IA86 - ajout breakpoint.....................["+address+"]");
        vm.addbreakpoint(vm.getCS(),stoi(address,nullptr,16));
        showInstr();
    }
}

//----------------------------------------------------------------------
// Fonction Main
//----------------------------------------------------------------------
int main (int argc, char* argv[])
{
  mapping();
  std::vector<std::string> args(argv, argv+argc);
  for (size_t i = 1; i < args.size(); ++i) {
      debugnow=(args[i] == "debug");
  }
  finalcut::FApplication app {argc, argv};
  Menu main_dlg {&app};
  finalcut::FWidget::setMainWidget (&main_dlg);
  return app.exec();
}
