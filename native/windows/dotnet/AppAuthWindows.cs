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

    /// <summary>
    /// Refreshes tokens on a worker thread and returns the updated
    /// serialized authentication state. The returned JSON contains sensitive
    /// tokens and must be stored securely.
    /// </summary>
    public static Task<string> RefreshAsync(
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
            var resultPointer = NativeMethods.Refresh(requestJson, cancellation);
            if (resultPointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("The native refresh call returned no result.");
            }
            using var result = new NativeMethods.AuthorizationResultHandle(resultPointer);

            var valuePointer = NativeMethods.ResultValue(result);
            var value = Marshal.PtrToStringUTF8(valuePointer)
                ?? throw new InvalidOperationException("The native refresh result is empty.");
            return NativeMethods.ResultStatus(result) switch
            {
                0 => value,
                2 => throw new OperationCanceledException(cancellationToken),
                _ => throw new InvalidOperationException(value),
            };
        }, CancellationToken.None);
    }

    /// <summary>
    /// Runs OIDC end-session (RP-initiated logout) on a worker thread.
    /// With a post-logout redirect URI, the returned JSON is the validated
    /// logout response; without one, the system browser is opened and the
    /// returned string is empty.
    /// </summary>
    public static Task<string> EndSessionAsync(
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
            var resultPointer = NativeMethods.EndSession(requestJson, cancellation);
            if (resultPointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("The native end-session call returned no result.");
            }
            using var result = new NativeMethods.AuthorizationResultHandle(resultPointer);

            var valuePointer = NativeMethods.ResultValue(result);
            var value = Marshal.PtrToStringUTF8(valuePointer)
                ?? throw new InvalidOperationException("The native end-session result is empty.");
            return NativeMethods.ResultStatus(result) switch
            {
                0 => value,
                2 => throw new OperationCanceledException(cancellationToken),
                _ => throw new InvalidOperationException(value),
            };
        }, CancellationToken.None);
    }

    /// <summary>
    /// Requests OAuth 2.0 token revocation on a worker thread.
    /// This does not delete local authentication state.
    /// </summary>
    public static Task RevokeAsync(
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
            var resultPointer = NativeMethods.Revoke(requestJson, cancellation);
            if (resultPointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("The native revocation call returned no result.");
            }
            using var result = new NativeMethods.AuthorizationResultHandle(resultPointer);

            var valuePointer = NativeMethods.ResultValue(result);
            var value = Marshal.PtrToStringUTF8(valuePointer)
                ?? throw new InvalidOperationException("The native revocation result is empty.");
            switch (NativeMethods.ResultStatus(result))
            {
                case 0:
                    return;
                case 2:
                    throw new OperationCanceledException(cancellationToken);
                default:
                    throw new InvalidOperationException(value);
            }
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
            EntryPoint = "appauth_windows_refresh")]
        internal static extern IntPtr Refresh(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson,
            CancellationHandle cancellation);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_end_session")]
        internal static extern IntPtr EndSession(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson,
            CancellationHandle cancellation);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true,
            EntryPoint = "appauth_windows_revoke")]
        internal static extern IntPtr Revoke(
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
