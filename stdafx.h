// stdafx.h�: fichier Include pour les fichiers Include syst�me standard,
// ou les fichiers Include sp�cifiques aux projets qui sont utilis�s fr�quemment,
// et sont rarement modifi�s
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // certains constructeurs CString seront explicites
#define _AFX_NO_MFC_CONTROLS_IN_DIALOGS         // supprimer la prise en charge des contr�les MFC dans les bo�tes de dialogue

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclure les en-t�tes Windows rarement utilis�s
#endif

#include <afx.h>
#include <afxwin.h>         // composants MFC principaux et standard
#include <afxext.h>         // extensions MFC
#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // Prise en charge MFC pour les contr�les communs Internet Explorer�4
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>                     // Prise en charge des MFC pour les contr�les communs Windows
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <iostream>


#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // certains constructeurs CString seront explicites

#include <atlbase.h>
#include <atlstr.h>

// TODO: faites r�f�rence ici aux en-t�tes suppl�mentaires n�cessaires au programme
