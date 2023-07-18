#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import datetime
import hashlib
import json
import logging
import traceback
import typing as tp
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser

import scoring as score

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class BaseField(abc.ABC):
    def __init__(self, required=False, nullable=False):
        self._required = required
        self._nullable = nullable
        self._value = None

    def is_valid(self) -> bool:
        return not self._required or self._nullable or not self._nullable and self._value is not None

    @property
    def get_value(self) -> tp.Any:
        return self._value

    def set_value(self, value: tp.Any):
        self._value = value


class CharField(BaseField):
    def __str__(self):
        return self.get_value if self.get_value is not None else ""

    def is_valid(self) -> bool:
        return BaseField.is_valid(self) and (self._value is None or isinstance(self._value, str))


class ArgumentsField(BaseField):
    @property
    def get_value(self) -> tp.Dict[str, tp.Any]:
        return self._value


class EmailField(BaseField):
    def is_valid(self) -> bool:
        return BaseField.is_valid(self) and \
            (self._value is None or self._value is not None and self._value.find("@") >= 0)


class PhoneField(BaseField):

    def set_value(self, value: tp.Any):
        self._value = str(value)

    def is_valid(self) -> bool:
        return BaseField.is_valid(self) and \
            (self._value is None or self._value is not None and len(self._value) == 11 and self._value[0] == "7")


class DateField(BaseField):
    _date_format = "%d.%m.%Y"  # формат даты DD.MM.YYYY

    def is_valid(self) -> bool:
        if not BaseField.is_valid(self):
            return False
        try:
            if self._value is not None:
                datetime.datetime.strptime(self._value, self._date_format)
            return True
        except ValueError:
            return False


class BirthDayField(DateField):
    _seconds_in_year_approx = 365.25 * 24 * 3600

    def is_valid(self) -> bool:
        if not DateField.is_valid(self):
            return False
        try:
            if self._value is not None:
                difference = datetime.datetime.now() - datetime.datetime.strptime(self._value, self._date_format)
                age = difference.total_seconds() / self._seconds_in_year_approx
                return 0 <= age <= 70
        except Exception as ex:
            logging.exception(ex)
            return False
        return True


class GenderField(BaseField):
    _allowed_genders = [0, 1, 2]

    def is_valid(self) -> bool:
        return BaseField.is_valid(self) and \
            (self._value is None or self._value is not None and self._value in self._allowed_genders)


class ClientIDsField(ArgumentsField):
    def is_valid(self) -> bool:
        return ArgumentsField.is_valid(self) and isinstance(self._value, list) and len(self._value) > 0 and all(
            [isinstance(client_id, int) for client_id in self._value])


class BaseRequest:
    def is_valid(self) -> bool:
        for field in self.__dict__.values():
            if isinstance(field, BaseField) and not field.is_valid():
                return False
        return True

    def parse_request(self, request: tp.Dict[str, str]) -> None:
        if not request:
            return
        for name, value in request.items():
            if name not in self.__dict__.keys():
                continue
            field = self.__dict__[name]
            if not isinstance(field, BaseField):
                continue
            field.set_value(value)


class ClientsInterestsRequest(BaseRequest):
    _ERROR_INTEREST = {"error": "some field invalid"}

    def __init__(self):
        self.client_ids = ClientIDsField(required=True)
        self.date = DateField(required=False, nullable=True)

    def get_answer(self, request: tp.Dict[str, str], ctx: tp.Dict[str, tp.Any]) -> tp.Tuple[tp.Dict[str, tp.Any], int]:
        self.parse_request(request)
        if not self.is_valid():
            return {"error": "some field invalid"}, INVALID_REQUEST
        else:
            interests = {client: score.get_interests(None, None) for client in self.client_ids.get_value}
            ctx["nclients"] = len(interests)
            return interests, OK


class OnlineScoreRequest(BaseRequest):
    _ADMIN_SCORE = {"score": 42}
    _ERROR_SCORE = {"error": ""}

    def __init__(self):
        self.first_name = CharField(required=False, nullable=True)
        self.last_name = CharField(required=False, nullable=True)
        self.email = EmailField(required=False, nullable=True)
        self.phone = PhoneField(required=False, nullable=True)
        self.birthday = BirthDayField(required=False, nullable=True)
        self.gender = GenderField(required=False, nullable=True)

    def _phone_email_exists(self) -> bool:
        return self.email.get_value is not None and self.phone.get_value is not None

    def _first_last_names_exists(self) -> bool:
        return self.first_name.get_value is not None and self.last_name.get_value is not None

    def _gender_birthday_exists(self) -> bool:
        return self.gender.get_value is not None and self.birthday.get_value is not None

    def is_valid(self) -> bool:
        if not BaseRequest.is_valid(self):
            return False
        return self._phone_email_exists() or self._first_last_names_exists() or self._gender_birthday_exists()

    def get_answer(self, store, request: tp.Dict[str, str], is_admin: bool) -> tp.Tuple[tp.Dict[str, tp.Any], int]:
        if is_admin:
            return self._ADMIN_SCORE, OK
        self.parse_request(request)
        if not self.is_valid():
            return self._ERROR_SCORE, INVALID_REQUEST
        return {"score": score.get_score(store, self.phone.get_value, self.email.get_value, self.birthday.get_value,
                                         self.gender.get_value, self.first_name, self.last_name)}, OK


class MethodRequest(BaseRequest):
    def __init__(self):
        self.account = CharField(required=False, nullable=True)
        self.login = CharField(required=True, nullable=True)
        self.token = CharField(required=True, nullable=True)
        self.arguments = ArgumentsField(required=True, nullable=True)
        self.method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login.get_value == ADMIN_LOGIN


def check_auth(request: MethodRequest):
    if request.is_admin:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        msg = str(request.account) + str(request.login) + SALT
    digest = hashlib.sha512(msg.encode('utf-8')).hexdigest()
    if digest == request.token.get_value:
        return True
    return False


def send_server_error_request() -> tp.Tuple[tp.Dict[str, str], int]:
    return {"error": "Internal server error"}, INTERNAL_ERROR


def send_invalid_request() -> tp.Tuple[tp.Dict[str, str], int]:
    return {"error": "Invalid request"}, INVALID_REQUEST


def send_invalid_auth_request() -> tp.Tuple[tp.Dict[str, str], int]:
    return {"error": "Forbidden"}, FORBIDDEN


def handle_method(request: tp.Dict[str, tp.Any], ctx: tp.Dict[str, tp.Any], store):
    handler = MethodRequest()
    handler.parse_request(request)
    if not handler.is_valid():
        return send_invalid_request()
    if not check_auth(handler):
        return send_invalid_auth_request()
    if handler.method.get_value == "online_score":
        ctx["has"] = handler.arguments.get_value
        return OnlineScoreRequest().get_answer(store, handler.arguments.get_value, handler.is_admin)
    elif handler.method.get_value == "clients_interests":
        return ClientsInterestsRequest().get_answer(handler.arguments.get_value, ctx)
    else:
        return send_invalid_request()


def method_handler(request: tp.Dict[str, tp.Dict[str, tp.Any]], ctx: tp.Dict[str, tp.Any], store):
    try:
        body = request.get("body", None)
        return handle_method(body, ctx, store)
    except Exception as ex:
        print(ex)
        traceback.print_exc()
        return send_server_error_request()


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    @staticmethod
    def get_request_id(headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        data_string = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception as ex:
            logging.exception(ex)
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
