// Copyright (c) 2021 Nomango

#include <sstream>
#include <iomanip>
#include "user_info.h"

using std::ostringstream;
using std::istringstream;

struct Request
{
	int user_id;
};

struct Response
{
	UserInfo* user_info;
};

template <>
struct json_bind<Request>
{
	void to_json(json& j, const Request& v)
	{
		jsonxx::to_json(j["user_id"], v.user_id);
	}

	void from_json(const json& j, Request& v)
	{
		jsonxx::from_json(j["user_id"], v.user_id);
	}
};

template <>
struct json_bind<Response>
{
	void to_json(json& j, const Response& v)
	{
		jsonxx::to_json(j["user_info"], v.user_info);
	}

	void from_json(const json& j, Response& v)
	{
		jsonxx::from_json(j["user_info"], v.user_info);
	}
};

// ��ȡ�û���Ϣ�ӿ�
class GetUserInfoHandler
{
public:
	// POST����
	void POST(istringstream& req, ostringstream& resp)
	{
		// �������󣬿���ֱ�ӷ����л��� Request �ṹ����
		Request req_body;
		req >> json_wrap(req_body);

		// ��ȡ�û���Ϣ
		UserInfo user_info = QueryUser(req_body.user_id);

		// ��Ӧ���󣬿���ֱ�����л����������
		Response resp_body = { &user_info };
		resp << std::setw(4) << json_wrap(resp_body);
	}
};
