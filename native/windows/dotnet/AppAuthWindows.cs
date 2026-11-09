using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace ProjectFlora.AppAuthRust;

/// <summary>Runs Windows browser authorization through the native Rust library.</summary>
public static class AppAuthWindows
{
    /// <summary>
    /// Runs authorization on a worker thread and returns serialized authentication state.
    /// The returned JSON contains sensitive tokens and must be stored securely.
    /// </summary>
    public static Task<string> AuthorizeAsync(
        string requestJson,
        CancellationToken cancellationToken = default)
    {
        if (requestJson is null)
        {
            throw new ArgumentNullException(nameof(requestJson));
        }

        return Task.Run(() =>
        {
            var cancellationPointer = NativeMethods.CreateCancellation();
            if (cancellationPointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("The native cancellation handle could not be created.");
            }
            using var cancellation = new NativeMethods.CancellationHandle(cancellationPointer);
            using var registration = cancellationToken.Register(
                () => NativeMethods.Cancel(cancellation));
            var resultPointer = NativeMethods.Authorize(requestJson, cancellation);
            if (resultPointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("The native authorization call returned no result.");
            }
            using var result = new NativeMethods.AuthorizationResultHandle(resultPointer);

            var valuePointer = NativeMethods.ResultValue(result);
            var value = Marshal.PtrToStringUTF8(valuePointer)
                ?? throw new InvalidOperationException("The native authorization result is empty.");
            return NativeMethods.ResultStatus(result) switch
            {
                0 => value,
                2 => throw new OperationCanceledException(cancellationToken),
                _ => throw new InvalidOperationException(value),
            };
        }, CancellationToken.None);
    }

    private static class NativeMethods
    {
        private const string Library = "appauth_rust.dll";

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_cancellation_new")]
        internal static extern IntPtr CreateCancellation();

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_cancellation_cancel")]
        internal static extern void Cancel(CancellationHandle handle);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_cancellation_free")]
        private static extern void FreeCancellation(IntPtr handle);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_authorize")]
        internal static extern IntPtr Authorize(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson,
            CancellationHandle cancellation);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_authorization_result_status")]
        internal static extern int ResultStatus(AuthorizationResultHandle result);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_authorization_result_value")]
        internal static extern IntPtr ResultValue(AuthorizationResultHandle result);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_authorization_result_free")]
        private static extern void FreeResult(IntPtr result);

        internal sealed class CancellationHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal CancellationHandle(IntPtr handle) : base(ownsHandle: true)
            {
                SetHandle(handle);
            }

            protected override bool ReleaseHandle()
            {
                FreeCancellation(handle);
                return true;
            }
        }

        internal sealed class AuthorizationResultHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal AuthorizationResultHandle(IntPtr handle) : base(ownsHandle: true)
            {
                SetHandle(handle);
            }

            protected override bool ReleaseHandle()
            {
                FreeResult(handle);
                return true;
            }
        }
    }
}
