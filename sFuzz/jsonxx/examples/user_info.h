// Copyright (c) 2021 Nomango

#include <jsonxx/json.hpp>

using namespace jsonxx;
using std::vector;
using std::string;

// �û���ɫ
struct UserRole
{
	// ��ɫ���
	int code;
	// Ȩ���б�
	vector<string> permission_list;
};

// �û���Ϣ
struct UserInfo
{
	// �û�id
	int user_id;
	// �û���
	string user_name;
	// ��ɫ�б�
	vector<UserRole> role_list;
};

extern UserInfo QueryUser(int user_id);

// ��json
template <>
struct json_bind<UserRole>
{
	void to_json(json& j, const UserRole& v)
	{
		jsonxx::to_json(j["code"], v.code);
		jsonxx::to_json(j["permission_list"], v.permission_list);
	}

	void from_json(const json& j, UserRole& v)
	{
		jsonxx::from_json(j["code"], v.code);
		jsonxx::from_json(j["permission_list"], v.permission_list);
	}
};

template <>
struct json_bind<UserInfo>
{
	void to_json(json& j, const UserInfo& v)
	{
		jsonxx::to_json(j["user_id"], v.user_id);
		jsonxx::to_json(j["user_name"], v.user_name);
		jsonxx::to_json(j["role_list"], v.role_list);
	}

	void from_json(const json& j, UserInfo& v)
	{
		jsonxx::from_json(j["user_id"], v.user_id);
		jsonxx::from_json(j["user_name"], v.user_name);
		jsonxx::from_json(j["role_list"], v.role_list);
	}
};
