# SDLC_Lab_4
Практика №4 по "Разработке безопасного программного обеспечения"

### 1. Необходимо найти участок кода, содержащий инъекцию SQL кода в задании Blind Sql Injection на сайте dvwa.local с использованием статического анализатора кода (Можно использовать официальный ресурс или виртуальную машину Web Security Dojo)

Для нахождения участка кода, содержащего инъекцию SQL в приложении используем два статический анализатор SonarCloud. 

Для начала загрузим код уровня low с SQL инъекцией на SonarCloud и посмотрим, какие недочеты обнаружит аналитор.

![Анализ SonarCloud low](imgs/sonar_low.png) ![Анализ SonarCloud high](imgs/sonar_high.png)

Можем увидеть, что анализатор указал, где находится уязвимость в программе на уровне low и на уровне high. SonarCloud указывает путь, по которому вредоносные данные могут попасть через пользовательский ввод в запрос к базе данных. В случае с уровнем low вредоносные данные могут попасть напрямую через пользовательский ввод с клавиатуры в поле формы. Например, если ввести "1' OR '1'='1", то приложение сообщит, что пользователь с таким id существует.

В случае с уровнем high, анализатор указал, что вредоносные данные могут попасть в запрос в базу данных через значение id в cookie, так как пользователь также может менять значения cookie, которые отправляются на сервер.

### 2. Проанализировать код и сделать кодревью, указав слабые места

Проанализируем код и укажем в комментариях проблемные участки кода с использованием метрики CWE.

```PHP
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
	$id = $_GET[ 'id' ];

	$getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"; 
	//Использование необработанного параметра HTTP запроса в SQL запроса в mysqli_query ведет к уязвимости CWE-89 SQL Injection. (1' OR '1'='1)
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid );

	$num = @mysqli_num_rows( $result );
	if( $num > 0 ) {
		$html .= '<pre>User ID exists in the database.</pre>';
	}
	else {
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        //CWE-209: Generation of Error Message Containing Sensitive Information. Информацию о ненахождении пользователя в бд - лишняя и может быть использована
        //злоумышленником для получения дополнительных сведений о внутреннем устройстве сервиса
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}

    //CWE-477: Use of Obsolete Function. В коде используются устаревшие или нерекомендуемые функции, что может вести к уязвимостям. В данном случае используется устаревшая функция mysqli_close
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```

### 3. Разработать свою систему вывода информации об объекте на любом языке, исключающий взможность инъекции SQL кода. Возможно исправление участка кода из dvwa.local Требования к системе авторизации. Система вывода информации об объекте должна использовать запросы GET с параметрами, аналогичными из задания Blind SQL injection dvwa

Разработаем аналогичную систему проверки существования id сущности с использованием Java Spring JDBC, где в качестве базы данных будет использоваться in memmory база данных H2. 

Таким образом, скрипт инициализации базы данных имеет следующий вид.

```SQL
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

INSERT INTO users (id, name) VALUES
    (45, 'Alex'),
    (34, 'Marty');
```

Код, обрабатывающий запрос и выполняющий запрос в базу данных выглядит следующим образом.

```Java
private static final String GET_USER_SQL = "SELECT id, name FROM users WHERE id = ?";
    private static final String IS_SUCCESS_ATTRIBUTE_NAME = "isSuccess";
    private static final String RESULT_ATTRIBUTE_NAME = "result";
    private static final String TEMPLATE_NAME = "page";

    private final JdbcTemplate jdbcTemplate;

    @GetMapping("/")
    public String makeRequest(@RequestParam(value = "id", required = false) String id,
                            @RequestParam(value = "Submit", required = false) String submit,
                            Model model) {
        if (id == null || submit == null) {
            model.addAttribute(IS_SUCCESS_ATTRIBUTE_NAME, null);
            return TEMPLATE_NAME;
        }

        long idParam = 0;
        try {
            idParam = Long.parseLong(id);
        } catch (NumberFormatException e) {
            model.addAttribute(IS_SUCCESS_ATTRIBUTE_NAME, false);
            return TEMPLATE_NAME;
        }
        var result = jdbcTemplate.queryForRowSet(GET_USER_SQL, idParam);
        if (result.next()) {
            model.addAttribute(RESULT_ATTRIBUTE_NAME,
                new String[] {result.getString("id"), result.getString("name")});
            model.addAttribute(IS_SUCCESS_ATTRIBUTE_NAME, true);
        } else {
            model.addAttribute(IS_SUCCESS_ATTRIBUTE_NAME, false);
        }

        return TEMPLATE_NAME;
    }
```

В данном участке кода принимается GET запрос сервером, и выполняется SQL запрос в базу данных с помощью JdbcTemplate, который предоставляет Spring JDBC. 

Перейдем на по адресу `http://localhost:8080` и проверим работу программы.

![JDBC успех](imgs/jdbc_success.png) ![JDBC провал](imgs/jdbc_fail.png)

### 4. Использовать sqlmap для нахождения уязвимости в веб-ресурсе

SqlMap - это инструмент с открытым исходным кодом, который автоматически находит и эксплуатирует уязвимости SQL-инъекций. Для начала используем этот инструмент на приложении DVWA для нахождения его уязвимостей.
