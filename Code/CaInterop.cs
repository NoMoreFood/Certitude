//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Runtime.InteropServices;

namespace Certitude
{
    // Vtable order and identifiers follow certview.h, certadm.h and certcli.h in the Windows SDK.

    // Each scope is created, used and disposed on the same worker thread; RCWs never reach the UI.
    internal sealed class ComScope<T> : IDisposable where T : class
    {
        public T Value { get; }

        public ComScope(T value) => Value = value;

        public static ComScope<T> Create(string progId)
        {
            // Activate the CA COM object inside the scope that owns its eventual release.
            var type = Type.GetTypeFromProgID(progId, true);
            return new ComScope<T>((T)Activator.CreateInstance(type));
        }

        public void Dispose()
        {
            // Release the native object before its owning worker leaves the COM scope.
            if (Value != null && Marshal.IsComObject(Value)) Marshal.FinalReleaseComObject(Value);
        }
    }

    internal sealed class VariantValue : IDisposable
    {
        public IntPtr Pointer { get; } = Marshal.AllocCoTaskMem(24);

        public VariantValue(object value, bool binaryString = true)
        {
            // Initialize the VARIANT so cleanup is safe even if conversion fails.
            for (var i = 0; i < 24; i++) Marshal.WriteByte(Pointer, i, 0);
            try
            {
                // Use ordinary marshaling unless the CA API requires a binary BSTR.
                if (value is not byte[] bytes || !binaryString)
                {
                    Marshal.GetNativeVariantForObject(value, Pointer);
                    return;
                }
                // Certificate properties and extensions use binary BSTRs; registry entries use native arrays.
                var bstr = SysAllocStringByteLen(bytes, (uint)bytes.Length);
                if (bstr == IntPtr.Zero) throw new OutOfMemoryException();
                Marshal.WriteInt16(Pointer, 8);
                Marshal.WriteIntPtr(Pointer, 8, bstr);
            }
            catch { Dispose(); throw; }
        }

        public void Dispose()
        {
            // Free both the VARIANT payload and the storage allocated for the native call.
            VariantClear(Pointer);
            Marshal.FreeCoTaskMem(Pointer);
        }

        [DllImport("oleaut32.dll")]
        private static extern IntPtr SysAllocStringByteLen(byte[] bytes, uint length);
        [DllImport("oleaut32.dll")]
        private static extern int VariantClear(IntPtr variant);
    }

    [ComImport, Guid("c3fac344-1e84-11d1-9bd6-00c04fb683fa"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface ICertView
    {
        void OpenConnection([MarshalAs(UnmanagedType.BStr)] string config);
        ICertViewColumn EnumCertViewColumn(int flags);
        int GetColumnCount(int flags);
        int GetColumnIndex(int flags, [MarshalAs(UnmanagedType.BStr)] string name);
        void SetResultColumnCount(int count);
        void SetResultColumn(int index);
        void SetRestriction(int index, int seek, int sort, [In, MarshalAs(UnmanagedType.Struct)] ref object value);
        ICertViewRow OpenView();
    }

    [ComImport, Guid("9c735be2-57a5-11d1-9bdb-00c04fb683fa"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface ICertViewColumn
    {
        int Next();
        [return: MarshalAs(UnmanagedType.BStr)] string GetName();
        [return: MarshalAs(UnmanagedType.BStr)] string GetDisplayName();
        int GetType();
        int IsIndexed();
        int GetMaxLength();
        [return: MarshalAs(UnmanagedType.Struct)] object GetValue(int flags);
        void Skip(int count);
        void Reset();
        ICertViewColumn Clone();
    }

    [ComImport, Guid("d1157f4c-5af2-11d1-9bdc-00c04fb683fa"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface ICertViewRow
    {
        int Next();
        ICertViewColumn EnumCertViewColumn();
        ICertViewAttribute EnumCertViewAttribute(int flags);
        ICertViewExtension EnumCertViewExtension(int flags);
        void Skip(int count);
        void Reset();
        ICertViewRow Clone();
        int GetMaxIndex();
    }

    [ComImport, Guid("e77db656-7653-11d1-9bde-00c04fb683fa"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface ICertViewAttribute
    {
        int Next();
        [return: MarshalAs(UnmanagedType.BStr)] string GetName();
        [return: MarshalAs(UnmanagedType.BStr)] string GetValue();
        void Skip(int count);
        void Reset();
        ICertViewAttribute Clone();
    }

    [ComImport, Guid("e7dd1466-7653-11d1-9bde-00c04fb683fa"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface ICertViewExtension
    {
        int Next();
        [return: MarshalAs(UnmanagedType.BStr)] string GetName();
        int GetFlags();
        [return: MarshalAs(UnmanagedType.Struct)] object GetValue(int type, int flags);
        void Skip(int count);
        void Reset();
        ICertViewExtension Clone();
    }

    [ComImport, Guid("f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface ICertAdmin
    {
        int IsValidCertificate([MarshalAs(UnmanagedType.BStr)] string config,
            [MarshalAs(UnmanagedType.BStr)] string serial);
        int GetRevocationReason();
        void RevokeCertificate([MarshalAs(UnmanagedType.BStr)] string config,
            [MarshalAs(UnmanagedType.BStr)] string serial, int reason, double date);
        void SetRequestAttributes([MarshalAs(UnmanagedType.BStr)] string config, int requestId,
            [MarshalAs(UnmanagedType.BStr)] string attributes);
        void SetCertificateExtension([MarshalAs(UnmanagedType.BStr)] string config, int requestId,
            [MarshalAs(UnmanagedType.BStr)] string name, int type, int flags,
            IntPtr value);
        void DenyRequest([MarshalAs(UnmanagedType.BStr)] string config, int requestId);
        int ResubmitRequest([MarshalAs(UnmanagedType.BStr)] string config, int requestId);
        void PublishCRL([MarshalAs(UnmanagedType.BStr)] string config, double date);
        [return: MarshalAs(UnmanagedType.BStr)] string GetCRL([MarshalAs(UnmanagedType.BStr)] string config, int flags);
        int ImportCertificate([MarshalAs(UnmanagedType.BStr)] string config,
            [MarshalAs(UnmanagedType.BStr)] string certificate, int flags);
        void PublishCRLs([MarshalAs(UnmanagedType.BStr)] string config, double date, int flags);
        [return: MarshalAs(UnmanagedType.Struct)] object GetCAProperty([MarshalAs(UnmanagedType.BStr)] string config,
            int propertyId, int index, int type, int flags);
        void SetCAProperty([MarshalAs(UnmanagedType.BStr)] string config, int propertyId, int index, int type,
            IntPtr value);
        int GetCAPropertyFlags([MarshalAs(UnmanagedType.BStr)] string config, int propertyId);
        [return: MarshalAs(UnmanagedType.BStr)] string GetCAPropertyDisplayName(
            [MarshalAs(UnmanagedType.BStr)] string config, int propertyId);
        [return: MarshalAs(UnmanagedType.BStr)] string GetArchivedKey([MarshalAs(UnmanagedType.BStr)] string config,
            int requestId, int flags);
        [return: MarshalAs(UnmanagedType.Struct)] object GetConfigEntry([MarshalAs(UnmanagedType.BStr)] string config,
            [MarshalAs(UnmanagedType.BStr)] string node, [MarshalAs(UnmanagedType.BStr)] string name);
        void SetConfigEntry([MarshalAs(UnmanagedType.BStr)] string config,
            [MarshalAs(UnmanagedType.BStr)] string node, [MarshalAs(UnmanagedType.BStr)] string name,
            IntPtr value);
        void ImportKey([MarshalAs(UnmanagedType.BStr)] string config, int requestId,
            [MarshalAs(UnmanagedType.BStr)] string hash, int flags, [MarshalAs(UnmanagedType.BStr)] string key);
        int GetMyRoles([MarshalAs(UnmanagedType.BStr)] string config);
        int DeleteRow([MarshalAs(UnmanagedType.BStr)] string config, int flags, double date, int table, int rowId);
    }

    [ComImport, Guid("014e4840-5523-11d0-8812-00a0c903b83c"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface ICertRequest
    {
        int Submit(int flags, [MarshalAs(UnmanagedType.BStr)] string request,
            [MarshalAs(UnmanagedType.BStr)] string attributes, [MarshalAs(UnmanagedType.BStr)] string config);
        int RetrievePending(int requestId, [MarshalAs(UnmanagedType.BStr)] string config);
        int GetLastStatus();
        int GetRequestId();
        [return: MarshalAs(UnmanagedType.BStr)] string GetDispositionMessage();
        [return: MarshalAs(UnmanagedType.BStr)] string GetCACertificate(int exchange,
            [MarshalAs(UnmanagedType.BStr)] string config, int flags);
        [return: MarshalAs(UnmanagedType.BStr)] string GetCertificate(int flags);
    }
}
