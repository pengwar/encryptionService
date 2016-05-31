/**
 * 
 */
package com.union.service;

import union.counter.api.UnionEncPin;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import android.widget.Toast;

import com.union.aidl.IEncryptionAidlInterface;

/**
 * @author Administrator
 * 
 */
public class RemoteService extends Service {

	private IEncryptionAidlInterface.Stub bind = new IEncryptionAidlInterface.Stub() {

		@Override
		public String encrypt(String password, String pk) throws RemoteException {
			UnionEncPin uep = new UnionEncPin();
			if (!password.matches("(.*)[a-zA-Z](.*)")) {
				try {
				return uep.UnionEncryptPinByPK("",password, pk);
				} catch (Exception e) {
					Log.d("加密失败", e+"");
				}
			} else {
				while (password.length() < 16) {
					password += "F";
				}
				try {
					return uep.UnionEncryptPinByPK("",password, pk);
				} catch (Exception e) {
					Log.d("加密失败", e+"");
				}
			}
			return "";
		}
	};

	@Override
	public void onCreate() {
		Toast.makeText(this, "开启服务", Toast.LENGTH_SHORT).show();
		super.onCreate();
	}

	@Override
	public void onDestroy() {
		Toast.makeText(this, "关闭服务", Toast.LENGTH_SHORT).show();
		super.onDestroy();
	}

	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		return super.onStartCommand(intent, flags, startId);
	}

	@Override
	public IBinder onBind(Intent intent) {
		return bind;
	}

}
